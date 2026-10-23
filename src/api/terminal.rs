use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use crate::auth::AuthenticatedOperator;

#[derive(Deserialize)]
pub struct TerminalExecPayload {
    pub command: String,
}

#[derive(Serialize)]
pub struct TerminalStatusResponse {
    pub allowed: bool,
    pub username: String,
    pub provider: String,
    pub message: String,
}

pub async fn get_terminal_status(
    operator: AuthenticatedOperator,
) -> impl IntoResponse {
    if operator.provider == "Postgres" {
        (
            StatusCode::FORBIDDEN,
            Json(TerminalStatusResponse {
                allowed: false,
                username: operator.username,
                provider: operator.provider,
                message: "Acesso Negado: O terminal do sistema operacional é restrito a administradores do Samba Active Directory ou operadores Linux (sudo/root). Superusuários PostgreSQL não possuem permissão de acesso ao terminal.".to_string(),
            }),
        )
    } else {
        (
            StatusCode::OK,
            Json(TerminalStatusResponse {
                allowed: true,
                username: operator.username,
                provider: operator.provider,
                message: "Terminal operacional autorizado.".to_string(),
            }),
        )
    }
}

pub async fn exec_terminal_cmd(
    operator: AuthenticatedOperator,
    Json(payload): Json<TerminalExecPayload>,
) -> impl IntoResponse {
    if operator.provider == "Postgres" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "Acesso negado: superusuários PostgreSQL não possuem permissão de terminal do sistema.",
                "allowed": false
            })),
        );
    }

    let cmd = payload.command.trim();
    if cmd.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Comando não pode ser vazio."
            })),
        );
    }

    match timeout(
        Duration::from_secs(15),
        Command::new("bash").arg("-c").arg(cmd).output(),
    )
    .await
    {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = out.status.code().unwrap_or(-1);
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code
                })),
            )
        }
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Falha ao executar comando: {}", e)
            })),
        ),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({
                "success": false,
                "error": "Timeout: comando excedeu o limite de 15 segundos."
            })),
        ),
    }
}
