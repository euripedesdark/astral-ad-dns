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
