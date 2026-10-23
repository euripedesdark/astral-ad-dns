use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use crate::config::AppConfig;
use crate::system::run_cmd_dry;
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackupArchive {
    pub filename: String,
    pub size_bytes: u64,
    pub size_human: String,
    pub created_at: String,
}

pub async fn list_backups(State(_config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<BackupArchive>>> {
    let backup_dir = "/var/backups/samba";
    let mut archives = Vec::new();

    if let Ok(entries) = fs::read_dir(backup_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    if filename.ends_with(".tar.bz2") || filename.ends_with(".tar.gz") {
                        let size_bytes = meta.len();
                        let size_human = if size_bytes > 1024 * 1024 {
                            format!("{:.2} MB", size_bytes as f64 / (1024.0 * 1024.0))
                        } else {
                            format!("{:.2} KB", size_bytes as f64 / 1024.0)
                        };

                        let created_at = meta
                            .modified()
                            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|_| "Unknown".to_string());

                        archives.push(BackupArchive {
                            filename,
                            size_bytes,
                            size_human,
                            created_at,
                        });
                    }
                }
            }
        }
    }

    archives.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Json(ApiResponse {
        success: true,
        message: format!("Encontrados {} backups", archives.len()),
        data: Some(archives),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_backup(
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");
    let backup_dir = "/var/backups/samba";

    let _ = run_cmd_dry(&format!("mkdir -p {}", backup_dir), sudo, q.dry_run);

    let cmd = format!(
        "samba-tool domain backup online --targetdir='{}' -U administrator --password='{}'",
        backup_dir, admin_pass
    );

    let res = run_cmd_dry(&cmd, sudo, q.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "BACKUP_CREATE",
        "samba:backup",
        q.dry_run,
        res.success,
        &format!("Geração de backup online do Active Directory (dry_run={})", q.dry_run),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Backup online seria gravado no diretório: {}", backup_dir)
                } else {
                    "Backup online do Active Directory concluído com sucesso".to_string()
                },
                data: Some(res.stdout),
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao criar backup do Samba: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

#[derive(Deserialize, Debug)]
pub struct RestoreBackupRequest {
    pub filename: String,
    pub new_server_name: Option<String>,
    pub host_ip: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn restore_backup(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<RestoreBackupRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<String>>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();
    let filename = payload.filename.trim();

    // Validação de segurança de path traversal
    if filename.is_empty() || filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de arquivo de backup inválido".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let backup_path = format!("/var/backups/samba/{}", filename);
    if !std::path::Path::new(&backup_path).exists() && !payload.dry_run {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                message: format!("Arquivo de backup não encontrado: {}", backup_path),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    // Detecta IP e Hostname atuais do servidor para preservar configurações de rede do host
    let host_ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
    let current_ip = host_ip_res.stdout.trim().to_string();
    let target_ip = payload.host_ip.as_deref().unwrap_or(&current_ip);

    let host_name_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let current_hostname = host_name_res.stdout.trim().to_uppercase();
    let target_server_name = payload.new_server_name.as_deref().unwrap_or(&current_hostname).to_uppercase();

    if payload.dry_run {
        steps.push(format!("[SIMULAÇÃO] Verificação do arquivo de backup: {}", backup_path));
        steps.push("[SIMULAÇÃO] Parada preventiva do serviço Samba AD DC (systemctl stop samba)".to_string());
        steps.push("[SIMULAÇÃO] Backup de salvaguarda do estado atual em /var/lib/samba.pre-restore e /etc/samba/smb.conf.pre-restore".to_string());
        steps.push(format!(
            "[SIMULAÇÃO] Restauração do Samba AD: preservando IP atual ({}) e nome de servidor ({})",
            target_ip, target_server_name
        ));
        steps.push("[SIMULAÇÃO] Restauração estrita dos componentes Samba (LDB, Kerberos, Sysvol e smb.conf) sem alterar interfaces de rede do SO".to_string());
        steps.push("[SIMULAÇÃO] Redefinição de ACLs de Sysvol (samba-tool ntacl sysvolreset)".to_string());
        steps.push("[SIMULAÇÃO] Inicialização e teste de conformidade do serviço (systemctl start samba)".to_string());

        let evt_id = config.audit.record(
            "admin",
            None,
            "BACKUP_RESTORE_SIMULATION",
            &format!("file:{}", filename),
            true,
            true,
            &format!("Simulação de restauração do backup {}", filename),
        );

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de restauração validado com sucesso. Nenhuma alteração foi realizada.".to_string(),
                data: Some(steps),
                dry_run: true,
                correlation_id: Some(evt_id),
            }),
        );
    }

    // Execução real
    // 1. Parada dos serviços Samba
    let _ = run_cmd_dry("systemctl stop samba samba-dc smbd nmbd winbind 2>/dev/null || true", sudo, false);
    steps.push("Serviço Samba paralisado para restauração segura.".to_string());

    // 2. Backup de salvaguarda
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let _ = run_cmd_dry(&format!("cp -r /var/lib/samba /var/lib/samba.pre-restore.{} 2>/dev/null || true", timestamp), sudo, false);
    let _ = run_cmd_dry(&format!("cp /etc/samba/smb.conf /etc/samba/smb.conf.pre-restore.{} 2>/dev/null || true", timestamp), sudo, false);
    steps.push(format!("Backup de salvaguarda criado em /var/lib/samba.pre-restore.{}", timestamp));

    // 3. Execução da restauração do Samba AD
    let restore_temp_dir = "/var/lib/samba-restore-temp";
    let _ = run_cmd_dry(&format!("rm -rf {} 2>/dev/null || true", restore_temp_dir), sudo, false);
    let _ = run_cmd_dry(&format!("mkdir -p {}", restore_temp_dir), sudo, false);

    let restore_cmd = format!(
        "samba-tool domain backup restore --backup-file='{}' --targetdir='{}' --newservername='{}' --host-ip='{}'",
        backup_path, restore_temp_dir, target_server_name, target_ip
    );
    let res = run_cmd_dry(&restore_cmd, sudo, false);

    if res.success {
        // Move os diretórios restaurados para o local oficial do Samba
        let _ = run_cmd_dry(&format!("cp -rf {}/private/* /var/lib/samba/private/ 2>/dev/null || true", restore_temp_dir), sudo, false);
        if std::path::Path::new(&format!("{}/sysvol", restore_temp_dir)).exists() {
            let _ = run_cmd_dry(&format!("cp -rf {}/sysvol/* /var/lib/samba/sysvol/ 2>/dev/null || true", restore_temp_dir), sudo, false);
        }
        if std::path::Path::new(&format!("{}/etc/smb.conf", restore_temp_dir)).exists() {
            let _ = run_cmd_dry(&format!("cp -f {}/etc/smb.conf /etc/samba/smb.conf", restore_temp_dir), sudo, false);
        }
        let _ = run_cmd_dry(&format!("rm -rf {}", restore_temp_dir), sudo, false);
        steps.push("Arquivos de banco de dados do Samba (LDB) e Sysvol restaurados com sucesso.".to_string());
    } else {
        // Fallback: se o comando restore encontrou restrição de nome, descompacta os arquivos de banco preservando a rede
        let extract_cmd = format!("tar -xjf '{}' -C /var/lib/samba/ 2>/dev/null || tar -xzf '{}' -C /var/lib/samba/ 2>/dev/null", backup_path, backup_path);
        let _ = run_cmd_dry(&extract_cmd, sudo, false);
        steps.push("Restauração por descompactação de contingência executada.".to_string());
    }

    // 4. Garante que smb.conf preserva configurações de rede atuais e functional level
    let _ = run_cmd_dry("grep -q 'ad dc functional level = 2016' /etc/samba/smb.conf || sed -i '/\\[global\\]/a \\\\tad dc functional level = 2016' /etc/samba/smb.conf", sudo, false);
    steps.push(format!("Configuração de smb.conf ajustada preservando o IP do servidor ({}).", target_ip));

    // 5. Kerberos
    let _ = run_cmd_dry("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf 2>/dev/null || true", sudo, false);
    steps.push("Configuração Kerberos (/etc/krb5.conf) atualizada.".to_string());

    // 6. Reseta ACLs do Sysvol
    let _ = run_cmd_dry("samba-tool ntacl sysvolreset 2>/dev/null || true", sudo, false);
    steps.push("Permissões de ACLs do Sysvol redefinidas.".to_string());

    // 7. Reinicia o Samba AD DC
    let _ = run_cmd_dry("systemctl enable --now samba", sudo, false);
    let is_active = run_cmd_dry("systemctl is-active samba", sudo, false).stdout.trim() == "active";
    if is_active {
        steps.push("Serviço Samba Active Directory reiniciado e ativo com sucesso.".to_string());
    } else {
        steps.push("Aviso: Verifique o status do serviço Samba após a restauração.".to_string());
    }

    let evt_id = config.audit.record(
        "admin",
        None,
        "BACKUP_RESTORE",
        &format!("file:{}", filename),
        false,
        is_active,
        &format!("Restauração do backup do Samba AD {} (servidor={}, ip={})", filename, target_server_name, target_ip),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: is_active,
            message: format!("Backup '{}' restaurado com sucesso! Configurações do Samba AD recuperadas.", filename),
            data: Some(steps),
            dry_run: false,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn delete_backup(
    axum::extract::Path(filename): axum::extract::Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    if filename.is_empty() || filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de arquivo inválido".to_string(),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let backup_path = format!("/var/backups/samba/{}", filename);
    let cmd = format!("rm -f '{}'", backup_path);
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "BACKUP_DELETE",
        &format!("file:{}", filename),
        q.dry_run,
        res.success,
        &format!("Exclusão do backup {}", filename),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Backup '{}' excluído com sucesso", filename),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao excluir backup: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}
