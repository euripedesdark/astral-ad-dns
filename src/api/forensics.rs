use axum::{extract::{Path, State}, http::{header, StatusCode}, response::{IntoResponse, Json, Response}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::{Arc, Mutex, OnceLock}};
use crate::{api::users::ApiResponse, auth::Administrator, config::AppConfig, system::run_ad_operation_value};

#[derive(Clone, Serialize)]
pub struct ForensicJob {
    pub id: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
}
static JOBS: OnceLock<Mutex<BTreeMap<String, ForensicJob>>> = OnceLock::new();
fn jobs() -> &'static Mutex<BTreeMap<String, ForensicJob>> { JOBS.get_or_init(|| Mutex::new(BTreeMap::new())) }

#[derive(Deserialize)]
pub struct CaptureRequest { pub baseline_id: Option<String>, pub label: Option<String> }

fn response(status: StatusCode, data: Option<Value>, message: String) -> Response {
    let mut response = (status, Json(ApiResponse { success: status.is_success(), message, data, dry_run: false, correlation_id: None })).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

pub async fn overview(_operator: Administrator, State(config): State<Arc<AppConfig>>) -> Response {
    read_operation(config, json!({"action": "overview"})).await
}

async fn read_operation(config: Arc<AppConfig>, request: Value) -> Response {
    let result = tokio::task::spawn_blocking(move || run_ad_operation_value("forensic", &request, config.sudo_password.as_deref())).await;
    match result {
        Ok(Ok(value)) => response(StatusCode::OK, Some(value["data"].clone()), "Evidências forenses disponíveis.".into()).into_response(),
        Ok(Err(error)) => response(StatusCode::BAD_REQUEST, None, error).into_response(),
        Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, None, "Falha no processamento forense.".into()).into_response(),
    }
}

pub async fn start_capture(operator: Administrator, State(config): State<Arc<AppConfig>>, Json(payload): Json<CaptureRequest>) -> Response {
    if payload.baseline_id.as_deref().is_some_and(|id| !valid_id(id, "snp_")) {
        return response(StatusCode::BAD_REQUEST, None, "Referência de captura inválida.".into()).into_response();
    }
    let id = format!("job_{:x}_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0), std::process::id());
    let job = ForensicJob { id: id.clone(), status: "running".into(), started_at: chrono::Utc::now().to_rfc3339(), finished_at: None, result: None, error: None };
    {
        let mut state = jobs().lock().unwrap_or_else(|e| e.into_inner());
        if state.values().any(|job| job.status == "running") {
            return response(StatusCode::CONFLICT, None, "Já há uma captura em andamento; aguarde a conclusão.".into()).into_response();
        }
        while state.len() >= 100 {
            if let Some(key) = state.keys().next().cloned() { state.remove(&key); } else { break; }
        }
        state.insert(id.clone(), job.clone());
    }
    let analyst = format!("{} ({})", operator.0.username, operator.0.provider);
    let request = json!({"action": "capture", "baseline_id": payload.baseline_id, "label": payload.label.unwrap_or_default(), "analyst": analyst});
    tokio::spawn(async move {
        let task_config = config.clone();
        let result = tokio::task::spawn_blocking(move || run_ad_operation_value("forensic", &request, task_config.sudo_password.as_deref())).await;
        let (status, data, error) = match result {
            Ok(Ok(value)) => ("completed", Some(value["data"].clone()), None),
            Ok(Err(error)) => ("failed", None, Some(error)),
            Err(_) => ("failed", None, Some("A tarefa de coleta foi interrompida.".into())),
        };
        config.audit.record(&analyst, None, "AD_FORENSIC_CAPTURE", &id, false, error.is_none(), "Coleta forense de metadados AD, DNS/GPO e SYSVOL; relatório HTML5");
        if let Some(job) = jobs().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
            job.status = status.into(); job.result = data; job.error = error;
            job.finished_at = Some(chrono::Utc::now().to_rfc3339());
        }
    });
    response(StatusCode::ACCEPTED, serde_json::to_value(job).ok(), "Captura iniciada. Acompanhe o processamento em tela.".into()).into_response()
}

pub async fn job_status(_operator: Administrator, Path(id): Path<String>) -> Response {
    let state = jobs().lock().unwrap_or_else(|e| e.into_inner());
    match state.get(&id) {
        Some(job) => response(StatusCode::OK, serde_json::to_value(job).ok(), "Estado da captura.".into()).into_response(),
        None => response(StatusCode::NOT_FOUND, None, "Tarefa não encontrada. Após reinício, consulte o histórico persistente de relatórios.".into()).into_response(),
    }
}
fn valid_id(id: &str, prefix: &str) -> bool {
    id.starts_with(prefix) && id.len() == prefix.len() + 32 && id[prefix.len()..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub async fn report(_operator: Administrator, Path(id): Path<String>, State(config): State<Arc<AppConfig>>) -> Response {
    if !valid_id(&id, "rep_") { return response(StatusCode::BAD_REQUEST, None, "Relatório inválido.".into()).into_response(); }
    read_operation(config, json!({"action": "report", "report_id": id})).await
}

pub async fn report_html(_operator: Administrator, Path(id): Path<String>, State(config): State<Arc<AppConfig>>) -> Response {
    if !valid_id(&id, "rep_") { return response(StatusCode::BAD_REQUEST, None, "Relatório inválido.".into()).into_response(); }
    let request = json!({"action": "html", "report_id": id});
    let result = tokio::task::spawn_blocking(move || run_ad_operation_value("forensic", &request, config.sudo_password.as_deref())).await;
    match result {
        Ok(Ok(value)) => (StatusCode::OK, [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"),
            (header::CACHE_CONTROL, "no-store"), (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ], value["data"]["html"].as_str().unwrap_or("").to_string()).into_response(),
        Ok(Err(error)) => response(StatusCode::BAD_REQUEST, None, error).into_response(),
        Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, None, "Falha ao abrir relatório.".into()).into_response(),
    }
}
