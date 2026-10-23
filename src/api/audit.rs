use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::config::AppConfig;
use crate::audit::AuditEvent;
use crate::api::users::ApiResponse;

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

pub async fn list_audit_events(
    State(config): State<Arc<AppConfig>>,
    Query(query): Query<AuditQuery>,
) -> Json<ApiResponse<Vec<AuditEvent>>> {
    let limit = query.limit.unwrap_or(100).min(500);
    let events = config.audit.list(limit);

    Json(ApiResponse {
        success: true,
        message: format!("Recuperados {} eventos de auditoria", events.len()),
        data: Some(events),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn clear_audit_events(
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<()>> {
    config.audit.clear();
    config.audit.record("admin", None, "AUDIT_CLEAR", "system:audit", false, true, "Histórico de auditoria limpo pelo administrador");

    Json(ApiResponse {
        success: true,
        message: "Histórico de auditoria limpo com sucesso".to_string(),
        data: None,
        dry_run: false,
        correlation_id: None,
    })
}
