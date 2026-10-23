use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, sanitize_arg};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComputerItem {
    pub name: String,
    pub is_dc: bool,
}

#[derive(Deserialize, Debug)]
pub struct CreateComputerRequest {
    pub computername: String,
    pub description: Option<String>,
}

pub async fn list_computers(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<ComputerItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool computer list", sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to list computers: {}", res.stderr),
            data: None,
        });
    }

    let computers: Vec<ComputerItem> = res
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|name| {
            let is_dc = name.to_uppercase().contains("DC") || name.ends_with('$');
            ComputerItem { name, is_dc }
        })
        .collect();

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} computers", computers.len()),
        data: Some(computers),
    })
}

pub async fn create_computer(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateComputerRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    if payload.computername.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Computer name is required".to_string(),
                data: None,
            }),
        );
    }

    let mut cmd = format!("samba-tool computer create '{}'", sanitize_arg(&payload.computername));
    if let Some(desc) = payload.description {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(&desc)));
    }

    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: format!("Computer '{}' created successfully", payload.computername),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to create computer: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn delete_computer(
    Path(computername): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool computer delete '{}'", sanitize_arg(&computername));
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Computer '{}' deleted successfully", computername),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to delete computer: {}", res.stderr),
                data: None,
            }),
        )
    }
}
