use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashSet;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, sanitize_arg};

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
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct SetPasswordRequest {
    pub password: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct ActionQuery {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

pub fn safe_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

pub async fn list_users(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<UserItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool user list", sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar usuários: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let admin_res = run_cmd_dry("samba-tool group listmembers 'Domain Admins'", sudo, false);
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
        message: format!("Recuperados {} usuários", users.len()),
        data: Some(users),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn get_user_groups(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<String>>> {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user getgroups '{}'", sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao obter grupos do usuário: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
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
        message: "Grupos do usuário recuperados".to_string(),
        data: Some(groups),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_user(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateUserRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    if !safe_username(&payload.username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de usuário inválido (use apenas letras, números, '.', '-' ou '_', máx 64 caracteres)".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    if payload.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "A senha deve conter no mínimo 8 caracteres".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
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

    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "USER_CREATE",
        &format!("user:{}", payload.username),
        payload.dry_run,
        res.success,
        &format!("Criação de usuário '{}'", payload.username),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Plano de criação do usuário '{}' validado com sucesso", payload.username)
                } else {
                    format!("Usuário '{}' criado com sucesso", payload.username)
                },
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao criar usuário: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_user(
    Path(username): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    if !safe_username(&username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de usuário inválido".to_string(),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    if username.eq_ignore_ascii_case("Administrator") || username.eq_ignore_ascii_case("krbtgt") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "Contas de sistema críticas (Administrator, krbtgt) não podem ser excluídas".to_string(),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool user delete '{}'", sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "USER_DELETE",
        &format!("user:{}", username),
        q.dry_run,
        res.success,
        &format!("Exclusão de usuário '{}'", username),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o usuário '{}' seria excluído do Active Directory", username)
                } else {
                    format!("Usuário '{}' excluído com sucesso", username)
                },
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
                message: format!("Falha ao excluir usuário: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn enable_user(
    Path(username): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user enable '{}'", sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "USER_ENABLE",
        &format!("user:{}", username),
        q.dry_run,
        res.success,
        &format!("Ativação de conta de usuário '{}'", username),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Conta '{}' seria ativada", username)
                } else {
                    format!("Usuário '{}' ativado com sucesso", username)
                },
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
                message: format!("Falha ao ativar usuário: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn disable_user(
    Path(username): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool user disable '{}'", sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "USER_DISABLE",
        &format!("user:{}", username),
        q.dry_run,
        res.success,
        &format!("Desativação de conta de usuário '{}'", username),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Conta '{}' seria desativada", username)
                } else {
                    format!("Usuário '{}' desativado com sucesso", username)
                },
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
                message: format!("Falha ao desativar usuário: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
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

    if payload.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "A nova senha deve ter no mínimo 8 caracteres".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!(
        "samba-tool user setpassword '{}' --newpassword='{}'",
        sanitize_arg(&username),
        sanitize_arg(&payload.password)
    );
    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "PASSWORD_RESET",
        &format!("user:{}", username),
        payload.dry_run,
        res.success,
        &format!("Troca de senha do usuário '{}'", username),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Validação de troca de senha para '{}' aprovada", username)
                } else {
                    format!("Senha do usuário '{}' atualizada com sucesso", username)
                },
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao atualizar senha: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_username() {
        assert!(safe_username("joao.silva"));
        assert!(safe_username("maria_admin"));
        assert!(safe_username("user-01"));
        assert!(!safe_username(""));
        assert!(!safe_username("user;rm -rf /"));
        assert!(!safe_username("user' or '1'='1"));
        assert!(!safe_username("user$name"));
    }
}
