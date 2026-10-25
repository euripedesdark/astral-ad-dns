use axum::{
    extract::{Multipart, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, run_ad_operation, shell_quote};
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
    _operator: crate::auth::Administrator,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");
    let backup_dir = "/var/backups/samba";

    let _ = run_cmd_dry(&format!("mkdir -p {}", backup_dir), sudo, q.dry_run);

    let cmd = format!(
        "samba-tool domain backup online --server=127.0.0.1 --targetdir='{}' -U administrator --password={}",
        backup_dir, shell_quote(admin_pass)
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

#[derive(Deserialize, Serialize, Debug)]
pub struct RestoreBackupRequest {
    pub filename: String,
    pub new_server_name: Option<String>,
    pub host_ip: Option<String>,
    #[serde(default)]
    pub replace_existing: bool,
    #[serde(default)]
    pub isolated_recovery_confirmed: bool,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn restore_backup(
    _operator: crate::auth::Administrator,
    State(config): State<Arc<AppConfig>>,
    Json(mut payload): Json<RestoreBackupRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<String>>>) {
    let sudo = config.sudo_password.as_deref();
    if payload.new_server_name.as_deref().unwrap_or("").is_empty() {
        payload.new_server_name = Some(run_cmd_dry("hostname -s", sudo, false).stdout.trim().to_uppercase());
    }
    if payload.host_ip.as_deref().unwrap_or("").is_empty() {
        payload.host_ip = Some(run_cmd_dry("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1", sudo, false).stdout.trim().to_string());
    }
    let result = run_ad_operation("restore", &serde_json::to_value(&payload).unwrap(), sudo);
    let id = config.audit.record(&_operator.0.username, None, "DOMAIN_BACKUP_RECOVERY", &payload.filename,
        payload.dry_run, result.is_ok(), "Provisionamento/recuperação de domínio a partir de backup Samba");
    match result {
        Ok(steps) => (StatusCode::OK, Json(ApiResponse {
            success: true,
            message: if payload.dry_run { "Plano de recuperação validado.".into() } else { "Domínio recuperado do backup e serviço validado.".into() },
            data: Some(steps), dry_run: payload.dry_run, correlation_id: Some(id),
        })),
        Err(error) => (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: error, data: None, dry_run: payload.dry_run, correlation_id: Some(id),
        })),
    }
}

pub async fn upload_backup(
    _operator: crate::auth::Administrator,State(config): State<Arc<AppConfig>>, mut multipart: Multipart) -> (StatusCode, Json<ApiResponse<String>>) {
    use tokio::io::AsyncWriteExt;
    let result: Result<String, String> = async {
        let mut field = multipart.next_field().await.map_err(|e| e.to_string())?.ok_or("Selecione um backup.")?;
        let original = field.file_name().ok_or("Arquivo sem nome.")?.to_string();
        if original.contains(['/', '\\', '\0']) || !(original.ends_with(".tar.bz2") || original.ends_with(".tar.gz")) {
            return Err("Use arquivo .tar.bz2 ou .tar.gz, sem caminhos no nome.".into());
        }
        let name = format!("import-{}-{}-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0), std::process::id(), original);
        let directory = std::path::Path::new("/var/backups/samba");
        tokio::fs::create_dir_all(directory).await.map_err(|e| e.to_string())?;
        let path = directory.join(&name);
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&path).await.map_err(|e| e.to_string())?;
        let transfer: Result<(), String> = async {
            let mut size = 0usize;
            while let Some(chunk) = field.chunk().await.map_err(|e| e.to_string())? {
                size += chunk.len();
                if size > 512 * 1024 * 1024 { return Err("Backup excede o limite de 512 MiB.".into()); }
                file.write_all(&chunk).await.map_err(|e| e.to_string())?;
            }
            if size == 0 { return Err("Arquivo vazio.".into()); }
            file.sync_all().await.map_err(|e| e.to_string())?;
            Ok(())
        }.await;
        if let Err(error) = transfer {
            drop(file);
            let _ = tokio::fs::remove_file(&path).await;
            return Err(error);
        }
        Ok(name)
    }.await;
    let id = config.audit.record(&_operator.0.username, None, "BACKUP_IMPORT", "samba:backup", false, result.is_ok(), "Importação de arquivo para recuperação");
    match result {
        Ok(name) => (StatusCode::CREATED, Json(ApiResponse { success: true, message: "Backup importado. A estrutura será validada antes da recuperação.".into(), data: Some(name), dry_run: false, correlation_id: Some(id) })),
        Err(error) => (StatusCode::BAD_REQUEST, Json(ApiResponse { success: false, message: error, data: None, dry_run: false, correlation_id: Some(id) })),
    }
}

pub async fn delete_backup(
    _operator: crate::auth::Administrator,
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
    let cmd = format!("rm -f -- {}", shell_quote(&backup_path));
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
