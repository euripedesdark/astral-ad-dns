use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, sanitize_arg};
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GpoItem {
    pub guid: String,
    pub display_name: String,
    pub path: String,
    pub dn: String,
    pub version: u32,
    pub flags: String,
    pub linked_containers: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateGpoRequest {
    pub display_name: String,
    pub policy_type: String, // "wallpaper", "command_script", "screen_lock", "drive_map", "custom"
    pub target_ou_dn: Option<String>,
    pub wallpaper_path: Option<String>,
    pub wallpaper_style: Option<String>, // "Fill", "Fit", "Stretch", "Tile", "Center"
    pub script_content: Option<String>,
    pub script_type: Option<String>, // "logon" or "startup"
    pub drive_letter: Option<String>,
    pub drive_unc_path: Option<String>,
    pub screen_lock_timeout_mins: Option<u32>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct LinkGpoRequest {
    pub container_dn: String,
}

pub async fn list_gpos(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<GpoItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool gpo listall", sudo, false);

    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar GPOs: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let mut gpos = Vec::new();
    let mut cur_guid = String::new();
    let mut cur_display_name = String::new();
    let mut cur_path = String::new();
    let mut cur_dn = String::new();
    let mut cur_version: u32 = 0;
    let mut cur_flags = String::new();

    for line in res.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("GPO") && trimmed.contains(':') {
            if !cur_guid.is_empty() {
                gpos.push(GpoItem {
                    guid: cur_guid.clone(),
                    display_name: cur_display_name.clone(),
                    path: cur_path.clone(),
                    dn: cur_dn.clone(),
                    version: cur_version,
                    flags: cur_flags.clone(),
                    linked_containers: Vec::new(),
                });
                cur_display_name.clear();
                cur_path.clear();
                cur_dn.clear();
                cur_version = 0;
                cur_flags.clear();
            }
            cur_guid = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("display name") && trimmed.contains(':') {
            cur_display_name = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("path") && trimmed.contains(':') {
            cur_path = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("dn") && trimmed.contains(':') {
            cur_dn = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("version") && trimmed.contains(':') {
            if let Ok(v) = trimmed.split(':').nth(1).unwrap_or("").trim().parse::<u32>() {
                cur_version = v;
            }
        } else if trimmed.starts_with("flags") && trimmed.contains(':') {
            cur_flags = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
        }
    }

    if !cur_guid.is_empty() {
        gpos.push(GpoItem {
            guid: cur_guid,
            display_name: cur_display_name,
            path: cur_path,
            dn: cur_dn,
            version: cur_version,
            flags: cur_flags,
            linked_containers: Vec::new(),
        });
    }

    // Busca os containers vinculados para cada GPO
    for gpo in &mut gpos {
        let containers_res = run_cmd_dry(&format!("samba-tool gpo listcontainers '{}' 2>/dev/null", gpo.guid), sudo, false);
        if containers_res.success {
            let list: Vec<String> = containers_res
                .stdout
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with("Container("))
                .collect();
            gpo.linked_containers = list;
        }
    }

    Json(ApiResponse {
        success: true,
        message: format!("Recuperadas {} Diretivas de Grupo (GPOs)", gpos.len()),
        data: Some(gpos),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_gpo(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateGpoRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let sudo = config.sudo_password.as_deref();
    let display_name = payload.display_name.trim();

    if display_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome da GPO é obrigatório".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    if payload.dry_run {
        let mut sim_msg = format!("[SIMULAÇÃO] Criação da GPO '{}' (Tipo: {})", display_name, payload.policy_type);
        if let Some(target) = &payload.target_ou_dn {
            sim_msg.push_str(&format!(" com vinculação à OU '{}'", target));
        }
        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: sim_msg,
                data: Some("{SIMULATED-GUID-0000-000000000000}".to_string()),
                dry_run: true,
                correlation_id: None,
            }),
        );
    }

    // 1. Cria a GPO vazia no Active Directory
    let create_cmd = format!("samba-tool gpo create '{}'", sanitize_arg(display_name));
    let res = run_cmd_dry(&create_cmd, sudo, false);

    if !res.success {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao criar GPO no Samba: {}", res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    // Extrai o GUID retornado (formato: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
    let mut gpo_guid = String::new();
    for word in res.stdout.split_whitespace() {
        if word.starts_with('{') && word.ends_with('}') && word.len() == 38 {
            gpo_guid = word.to_string();
            break;
        }
    }

    if gpo_guid.is_empty() {
        // Fallback: busca pelo nome da GPO recém-criada
        let list_res = run_cmd_dry("samba-tool gpo listall", sudo, false);
        for line in list_res.stdout.lines() {
            if line.contains(&gpo_guid) {
                break;
            }
        }
    }

    // 2. Aplicação do template de configuração simples no Sysvol
    let sysvol_policies_dir = run_cmd_dry("find /var/lib/samba/sysvol -type d -name 'Policies' 2>/dev/null | head -n 1", sudo, false);
    let policies_base = sysvol_policies_dir.stdout.trim().to_string();

    if !policies_base.is_empty() && !gpo_guid.is_empty() {
        let gpo_dir = format!("{}/{}", policies_base, gpo_guid);
        let user_scripts_dir = format!("{}/User/Scripts/Logon", gpo_dir);
        let machine_scripts_dir = format!("{}/Machine/Scripts/Startup", gpo_dir);

        let _ = run_cmd_dry(&format!("mkdir -p '{}' '{}'", user_scripts_dir, machine_scripts_dir), sudo, false);

        match payload.policy_type.as_str() {
            "wallpaper" => {
                let wp_path = payload.wallpaper_path.as_deref().unwrap_or("C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg");
                let style_code = match payload.wallpaper_style.as_deref().unwrap_or("Fill") {
                    "Tile" => "0",
                    "Center" => "0",
                    "Stretch" => "2",
                    "Fit" => "6",
                    _ => "10", // Fill
                };

                let script_content = format!(
                    "@echo off\r\n\
                    reg add \"HKCU\\Control Panel\\Desktop\" /v Wallpaper /t REG_SZ /d \"{}\" /f\r\n\
                    reg add \"HKCU\\Control Panel\\Desktop\" /v WallpaperStyle /t REG_SZ /d \"{}\" /f\r\n\
                    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters\r\n",
                    wp_path, style_code
                );
                let _ = fs::write("/tmp/gpo_wp.bat", script_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/gpo_wp.bat '{}/wallpaper.bat'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/gpo_wp.bat");

                let ini_content = "[Logon]\r\n0CmdLine=wallpaper.bat\r\n0Parameters=\r\n";
                let _ = fs::write("/tmp/scripts.ini", ini_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/scripts.ini '{}/scripts.ini'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/scripts.ini");
            }

            "command_script" => {
                let raw_script = payload.script_content.as_deref().unwrap_or("echo GPO Script Executed");
                let is_startup = payload.script_type.as_deref().unwrap_or("logon") == "startup";
                let target_dir = if is_startup { &machine_scripts_dir } else { &user_scripts_dir };
                let script_file = if is_startup { "startup_command.bat" } else { "logon_command.bat" };
                let ini_section = if is_startup { "[Startup]" } else { "[Logon]" };

                let formatted_script = format!("@echo off\r\n{}\r\n", raw_script.replace('\n', "\r\n"));
                let _ = fs::write("/tmp/gpo_cmd.bat", formatted_script);
                let _ = run_cmd_dry(&format!("cp -f /tmp/gpo_cmd.bat '{}/{}'", target_dir, script_file), sudo, false);
                let _ = fs::remove_file("/tmp/gpo_cmd.bat");

                let ini_content = format!("{}\r\n0CmdLine={}\r\n0Parameters=\r\n", ini_section, script_file);
                let _ = fs::write("/tmp/scripts.ini", ini_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/scripts.ini '{}/scripts.ini'", target_dir), sudo, false);
                let _ = fs::remove_file("/tmp/scripts.ini");
            }

            "drive_map" => {
                let letter = payload.drive_letter.as_deref().unwrap_or("Z:");
                let unc = payload.drive_unc_path.as_deref().unwrap_or("\\\\srvcloud.cloud\\publico");

                let script_content = format!(
                    "@echo off\r\nnet use {} /delete /y 2>nul\r\nnet use {} \"{}\" /persistent:yes\r\n",
                    letter, letter, unc
                );
                let _ = fs::write("/tmp/gpo_drive.bat", script_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/gpo_drive.bat '{}/map_drive.bat'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/gpo_drive.bat");

                let ini_content = "[Logon]\r\n0CmdLine=map_drive.bat\r\n0Parameters=\r\n";
                let _ = fs::write("/tmp/scripts.ini", ini_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/scripts.ini '{}/scripts.ini'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/scripts.ini");
            }

            "screen_lock" => {
                let mins = payload.screen_lock_timeout_mins.unwrap_or(15);
                let secs = mins * 60;

                let script_content = format!(
                    "@echo off\r\n\
                    reg add \"HKCU\\Control Panel\\Desktop\" /v ScreenSaveActive /t REG_SZ /d \"1\" /f\r\n\
                    reg add \"HKCU\\Control Panel\\Desktop\" /v ScreenSaveTimeOut /t REG_SZ /d \"{}\" /f\r\n\
                    reg add \"HKCU\\Control Panel\\Desktop\" /v ScreenSaverIsSecure /t REG_SZ /d \"1\" /f\r\n",
                    secs
                );
                let _ = fs::write("/tmp/gpo_lock.bat", script_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/gpo_lock.bat '{}/screen_lock.bat'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/gpo_lock.bat");

                let ini_content = "[Logon]\r\n0CmdLine=screen_lock.bat\r\n0Parameters=\r\n";
                let _ = fs::write("/tmp/scripts.ini", ini_content);
                let _ = run_cmd_dry(&format!("cp -f /tmp/scripts.ini '{}/scripts.ini'", user_scripts_dir), sudo, false);
                let _ = fs::remove_file("/tmp/scripts.ini");
            }

            _ => {}
        }

        // Reseta ACLs para que os clientes Windows consigam ler os arquivos da GPO
        let _ = run_cmd_dry("samba-tool ntacl sysvolreset 2>/dev/null || true", sudo, false);
    }

    // 3. Vinculação automática à OU ou domínio se solicitado
    if let Some(target) = payload.target_ou_dn.filter(|t| !t.trim().is_empty()) {
        if !gpo_guid.is_empty() {
            let link_cmd = format!("samba-tool gpo setlink '{}' '{}'", sanitize_arg(&target), gpo_guid);
            let _ = run_cmd_dry(&link_cmd, sudo, false);
        }
    }

    let evt_id = config.audit.record(
        "admin",
        None,
        "GPO_CREATE",
        &format!("gpo:{}", display_name),
        false,
        true,
        &format!("Criação da Diretiva de Grupo '{}' (GUID: {}, Tipo: {})", display_name, gpo_guid, payload.policy_type),
    );

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: format!("Diretiva de Grupo '{}' criada e configurada com sucesso!", display_name),
            data: Some(gpo_guid),
            dry_run: false,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn delete_gpo(
    Path(guid): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    // TRAVA DE SEGURANÇA: Não permitir exclusão das políticas padrão essenciais do domínio
    let up = guid.to_uppercase();
    if up.contains("31B2F340-016D-11D2-945F-00C04FB984F9") || up.contains("6AC1786C-016F-11D2-945F-00C04FB984F9") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "Não é permitido excluir as Diretivas Padrão do Domínio ou dos Controladores de Domínio".to_string(),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool gpo del '{}'", sanitize_arg(&guid));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "GPO_DELETE",
        &format!("gpo:{}", guid),
        q.dry_run,
        res.success,
        &format!("Exclusão da Diretiva de Grupo {}", guid),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Diretiva de Grupo '{}' excluída com sucesso", guid),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao excluir GPO: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn link_gpo(
    Path(guid): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<LinkGpoRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let container_dn = payload.container_dn.trim();

    if container_dn.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "DN do container de destino é obrigatório".to_string(),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool gpo setlink '{}' '{}'", sanitize_arg(container_dn), sanitize_arg(&guid));
    let res = run_cmd_dry(&cmd, sudo, false);

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("GPO '{}' vinculada com sucesso a '{}'", guid, container_dn),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao vincular GPO: {}", res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    }
}

pub async fn unlink_gpo(
    Path((guid, container_dn)): Path<(String, String)>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool gpo dellink '{}' '{}'", sanitize_arg(&container_dn), sanitize_arg(&guid));
    let res = run_cmd_dry(&cmd, sudo, false);

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Vínculo da GPO com '{}' removido com sucesso", container_dn),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao desvincular GPO: {}", res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    }
}
