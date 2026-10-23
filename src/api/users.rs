use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashSet;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, sanitize_arg};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserItem {
    pub username: String,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub groups: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub mail: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SetPasswordRequest {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

pub async fn list_users(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<UserItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool user list", sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to list users: {}", res.stderr),
            data: None,
        });
    }

    let admin_res = run_safe_cmd("samba-tool group listmembers 'Domain Admins'", sudo);
    let admin_set: HashSet<String> = admin_res
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut users = Vec::new();
    for line in res.stdout.lines() {
        let username = line.trim().to_string();
        if username.is_empty() {
            continue;
        }

        let is_admin = admin_set.contains(&username) || username.eq_ignore_ascii_case("Administrator");
        let is_disabled = username.eq_ignore_ascii_case("Guest") || username.eq_ignore_ascii_case("krbtgt");

        users.push(UserItem {
            username,
            is_admin,
            is_disabled,
            groups: Vec::new(),
        });
    }

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} users", users.len()),
        data: Some(users),
    })
}

pub async fn get_user_groups(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<String>>> {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user getgroups '{}'", sanitize_arg(&username));
    let res = run_safe_cmd(&cmd, sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to get user groups: {}", res.stderr),
            data: None,
        });
    }

    let groups: Vec<String> = res
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Json(ApiResponse {
        success: true,
        message: "Retrieved user groups".to_string(),
        data: Some(groups),
    })
}

pub async fn create_user(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateUserRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    if payload.username.trim().is_empty() || payload.password.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Username and password are required".to_string(),
                data: None,
            }),
        );
    }

    let mut cmd = format!(
        "samba-tool user create '{}' '{}'",
        sanitize_arg(&payload.username),
        sanitize_arg(&payload.password)
    );

    if let Some(given) = &payload.given_name {
        cmd.push_str(&format!(" --given-name='{}'", sanitize_arg(given)));
    }
    if let Some(sur) = &payload.surname {
        cmd.push_str(&format!(" --surname='{}'", sanitize_arg(sur)));
    }
    if let Some(mail) = &payload.mail {
        cmd.push_str(&format!(" --mail-address='{}'", sanitize_arg(mail)));
    }
    if let Some(desc) = &payload.description {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(desc)));
    }

    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' created successfully", payload.username),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to create user: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn delete_user(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user delete '{}'", sanitize_arg(&username));
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' deleted successfully", username),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to delete user: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn enable_user(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user enable '{}'", sanitize_arg(&username));
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' enabled", username),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to enable user: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn disable_user(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user disable '{}'", sanitize_arg(&username));
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' disabled", username),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to disable user: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn set_password(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<SetPasswordRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!(
        "samba-tool user setpassword '{}' --newpassword='{}'",
        sanitize_arg(&username),
        sanitize_arg(&payload.password)
    );
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Password for '{}' updated successfully", username),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to update password: {}", res.stderr),
                data: None,
            }),
        )
    }
}
