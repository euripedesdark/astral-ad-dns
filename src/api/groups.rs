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
pub struct GroupItem {
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateGroupRequest {
    pub groupname: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct GroupMemberRequest {
    pub username: String,
}

pub async fn list_groups(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<GroupItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool group list", sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to list groups: {}", res.stderr),
            data: None,
        });
    }

    let groups: Vec<GroupItem> = res
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|name| GroupItem { name })
        .collect();

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} groups", groups.len()),
        data: Some(groups),
    })
}

pub async fn get_group_members(
    Path(groupname): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<String>>> {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool group listmembers '{}'", sanitize_arg(&groupname));
    let res = run_safe_cmd(&cmd, sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to get group members: {}", res.stderr),
            data: None,
        });
    }

    let members: Vec<String> = res
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Json(ApiResponse {
        success: true,
        message: "Retrieved group members".to_string(),
        data: Some(members),
    })
}

pub async fn create_group(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateGroupRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    if payload.groupname.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Group name is required".to_string(),
                data: None,
            }),
        );
    }

    let mut cmd = format!("samba-tool group add '{}'", sanitize_arg(&payload.groupname));
    if let Some(desc) = payload.description {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(&desc)));
    }

    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: format!("Group '{}' created successfully", payload.groupname),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to create group: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn delete_group(
    Path(groupname): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool group delete '{}'", sanitize_arg(&groupname));
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Group '{}' deleted successfully", groupname),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to delete group: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn add_group_member(
    Path(groupname): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<GroupMemberRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!(
        "samba-tool group addmembers '{}' '{}'",
        sanitize_arg(&groupname),
        sanitize_arg(&payload.username)
    );
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Added '{}' to group '{}'", payload.username, groupname),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to add member: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn remove_group_member(
    Path((groupname, username)): Path<(String, String)>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!(
        "samba-tool group removemembers '{}' '{}'",
        sanitize_arg(&groupname),
        sanitize_arg(&username)
    );
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Removed '{}' from group '{}'", username, groupname),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to remove member: {}", res.stderr),
                data: None,
            }),
        )
    }
}
