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
    #[serde(default)]
    pub has_wheel: bool,
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

    let wheel_res = run_cmd_dry("getent group wheel", sudo, false);
    let wheel_set: HashSet<String> = if wheel_res.success {
        wheel_res
            .stdout
            .split(':')
            .nth(3)
            .map(|s| {
                s.split(',')
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        HashSet::new()
    };

    let mut users = Vec::new();
    for line in res.stdout.lines() {
        let username = line.trim().to_string();
        if username.is_empty() {
            continue;
        }

        let is_admin = admin_set.contains(&username) || username.eq_ignore_ascii_case("Administrator");
        let is_disabled = username.eq_ignore_ascii_case("Guest") || username.eq_ignore_ascii_case("krbtgt");

        let has_wheel = wheel_set.contains(&username);
        users.push(UserItem {
            username,
            is_admin,
            is_disabled,
            groups: Vec::new(),
            has_wheel,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateUserGroupsRequest {
    pub groups: Vec<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn update_user_groups(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<UpdateUserGroupsRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    if !safe_username(&username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de usuário inválido".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    if payload.dry_run {
        let evt_id = config.audit.record(
            "admin",
            None,
            "UPDATE_USER_GROUPS_DRY",
            &format!("user:{}", username),
            true,
            true,
            &format!("Simulação de alteração de grupos para '{}'", username),
        );
        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("[SIMULAÇÃO] Grupos de '{}' seriam atualizados", username),
                data: None,
                dry_run: true,
                correlation_id: Some(evt_id),
            }),
        );
    }

    // 1. Obter grupos atuais
    let cur_res = run_cmd_dry(&format!("samba-tool user getgroups '{}'", sanitize_arg(&username)), sudo, false);
    let current_groups: std::collections::HashSet<String> = if cur_res.success {
        cur_res.stdout.lines().map(|l| l.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        std::collections::HashSet::new()
    };

    let desired_groups: std::collections::HashSet<String> = payload.groups.into_iter().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect();

    // Grupos para adicionar
    for grp in desired_groups.difference(&current_groups) {
        let cmd = format!("samba-tool group addmembers '{}' '{}'", sanitize_arg(grp), sanitize_arg(&username));
        let _ = run_cmd_dry(&cmd, sudo, false);
    }

    // Grupos para remover (evita remover o grupo padrão principal Domain Users)
    for grp in current_groups.difference(&desired_groups) {
        if grp.eq_ignore_ascii_case("Domain Users") {
            continue;
        }
        let cmd = format!("samba-tool group removemembers '{}' '{}'", sanitize_arg(grp), sanitize_arg(&username));
        let _ = run_cmd_dry(&cmd, sudo, false);
    }

    let evt_id = config.audit.record(
        "admin",
        None,
        "UPDATE_USER_GROUPS",
        &format!("user:{}", username),
        false,
        true,
        &format!("Grupos do usuário '{}' atualizados com sucesso", username),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Grupos do usuário '{}' atualizados com sucesso", username),
            data: None,
            dry_run: false,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn add_user_to_group(
    Path((username, groupname)): Path<(String, String)>,
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
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool group addmembers '{}' '{}'", sanitize_arg(&groupname), sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, false);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Usuário '{}' adicionado ao grupo '{}'", username, groupname),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao adicionar grupo: {}", res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    }
}

pub async fn remove_user_from_group(
    Path((username, groupname)): Path<(String, String)>,
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
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool group removemembers '{}' '{}'", sanitize_arg(&groupname), sanitize_arg(&username));
    let res = run_cmd_dry(&cmd, sudo, false);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Usuário '{}' removido do grupo '{}'", username, groupname),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao remover grupo: {}", res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProperties {
    pub username: String,
    pub distinguished_name: String,
    pub display_name: String,
    pub given_name: String,
    pub surname: String,
    pub mail: String,
    pub description: String,
    pub telephone_number: String,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub password_never_expires: bool,
    pub user_account_control: u32,
    pub permissions_summary: Vec<String>,
    pub groups: Vec<String>,
    pub when_created: String,
    pub when_changed: String,
    pub last_logon: String,
    pub bad_pwd_count: u32,
    pub raw_ldif: String,
}

pub async fn get_user_properties(
    Path(username): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<UserProperties>>) {
    let sudo = config.sudo_password.as_deref();
    if !safe_username(&username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome de usuário inválido".to_string(),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let ldb_cmd = format!(
        "ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName={})'",
        sanitize_arg(&username)
    );
    let ldb_res = run_cmd_dry(&ldb_cmd, sudo, false);

    let raw_ldif = if ldb_res.success {
        ldb_res.stdout.clone()
    } else {
        String::new()
    };

    let mut distinguished_name = format!("CN={},CN=Users", username);
    let mut display_name = username.clone();
    let mut given_name = String::new();
    let mut surname = String::new();
    let mut mail = String::new();
    let mut description = String::new();
    let mut telephone_number = String::new();
    let mut user_account_control: u32 = 512;
    let mut when_created = String::new();
    let mut when_changed = String::new();
    let mut last_logon = String::new();
    let mut bad_pwd_count: u32 = 0;
    let mut groups: Vec<String> = Vec::new();

    for line in raw_ldif.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("dn:") {
            distinguished_name = trimmed.trim_start_matches("dn:").trim().to_string();
        } else if trimmed.starts_with("distinguishedName:") {
            distinguished_name = trimmed.trim_start_matches("distinguishedName:").trim().to_string();
        } else if trimmed.starts_with("displayName:") {
            display_name = trimmed.trim_start_matches("displayName:").trim().to_string();
        } else if trimmed.starts_with("givenName:") {
            given_name = trimmed.trim_start_matches("givenName:").trim().to_string();
        } else if trimmed.starts_with("sn:") {
            surname = trimmed.trim_start_matches("sn:").trim().to_string();
        } else if trimmed.starts_with("mail:") {
            mail = trimmed.trim_start_matches("mail:").trim().to_string();
        } else if trimmed.starts_with("description:") {
            description = trimmed.trim_start_matches("description:").trim().to_string();
        } else if trimmed.starts_with("telephoneNumber:") {
            telephone_number = trimmed.trim_start_matches("telephoneNumber:").trim().to_string();
        } else if trimmed.starts_with("userAccountControl:") {
            if let Ok(v) = trimmed.trim_start_matches("userAccountControl:").trim().parse::<u32>() {
                user_account_control = v;
            }
        } else if trimmed.starts_with("whenCreated:") {
            when_created = trimmed.trim_start_matches("whenCreated:").trim().to_string();
        } else if trimmed.starts_with("whenChanged:") {
            when_changed = trimmed.trim_start_matches("whenChanged:").trim().to_string();
        } else if trimmed.starts_with("lastLogonTimestamp:") || trimmed.starts_with("lastLogon:") {
            last_logon = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("badPwdCount:") {
            if let Ok(v) = trimmed.trim_start_matches("badPwdCount:").trim().parse::<u32>() {
                bad_pwd_count = v;
            }
        } else if trimmed.starts_with("memberOf:") {
            let grp_dn = trimmed.trim_start_matches("memberOf:").trim();
            let grp_name = if let Some(cn_part) = grp_dn.split(',').next() {
                cn_part.trim_start_matches("CN=").trim().to_string()
            } else {
                grp_dn.to_string()
            };
            if !groups.contains(&grp_name) {
                groups.push(grp_name);
            }
        }
    }

    if !groups.contains(&"Domain Users".to_string()) {
        groups.push("Domain Users".to_string());
    }

    // Avaliação de permissões e flags
    let is_disabled = (user_account_control & 0x0002) != 0;
    let password_never_expires = (user_account_control & 0x10000) != 0;
    let is_admin = username.to_lowercase() == "administrator"
        || groups.iter().any(|g| {
            let up = g.to_uppercase();
            up.contains("ADMIN") || up == "DOMAIN ADMINS" || up == "ENTERPRISE ADMINS" || up == "SCHEMA ADMINS"
        });

    let mut permissions_summary = Vec::new();
    if is_admin {
        permissions_summary.push("Privilégio de Administrador Total do Domínio (Domain Admins / Administrators)".to_string());
    }
    if is_disabled {
        permissions_summary.push("Conta Desativada (ACCOUNTDISABLE)".to_string());
    } else {
        permissions_summary.push("Conta Ativa e Operacional".to_string());
    }
    if password_never_expires {
        permissions_summary.push("Senha Nunca Expira (DONT_EXPIRE_PASSWORD)".to_string());
    } else {
        permissions_summary.push("Sujeito à Política de Expiração de Senha Padrão".to_string());
    }
    if (user_account_control & 0x0020) != 0 {
        permissions_summary.push("Senha Não Obrigatória (PASSWD_NOTREQD)".to_string());
    }
    if (user_account_control & 0x0040) != 0 {
        permissions_summary.push("Usuário Não Pode Alterar Senha (PASSWD_CANT_CHANGE)".to_string());
    }
    if (user_account_control & 0x0010) != 0 {
        permissions_summary.push("Bloqueio por Tentativas Inválidas (LOCKOUT)".to_string());
    }

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Propriedades do usuário '{}' carregadas com sucesso", username),
            data: Some(UserProperties {
                username,
                distinguished_name,
                display_name,
                given_name,
                surname,
                mail,
                description,
                telephone_number,
                is_admin,
                is_disabled,
                password_never_expires,
                user_account_control,
                permissions_summary,
                groups,
                when_created,
                when_changed,
                last_logon,
                bad_pwd_count,
                raw_ldif,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
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
