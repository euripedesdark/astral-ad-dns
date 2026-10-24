use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, shell_quote};
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupItem {
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateGroupRequest {
    pub groupname: String,
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct GroupMemberRequest {
    pub username: String,
    #[serde(default)]
    pub dry_run: bool,
}

const PROTECTED_GROUPS: &[&str] = &[
    "domain admins",
    "schema admins",
    "enterprise admins",
    "domain users",
    "domain controllers",
    "dnsadmins",
    "group policy creator owners",
];

pub async fn list_groups(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<GroupItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool group list", sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar grupos: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
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
        message: format!("Recuperados {} grupos", groups.len()),
        data: Some(groups),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn get_group_members(
    Path(groupname): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<String>>> {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool group listmembers {}", shell_quote(&groupname));
    let res = run_cmd_dry(&cmd, sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao obter membros do grupo: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
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
        message: "Membros do grupo recuperados".to_string(),
        data: Some(members),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_group(
    _operator: crate::auth::Administrator,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateGroupRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    if payload.groupname.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome do grupo é obrigatório".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let mut cmd = format!("samba-tool group add {}", shell_quote(&payload.groupname));
    if let Some(desc) = payload.description {
        cmd.push_str(&format!(" --description={}", shell_quote(&desc)));
    }

    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "GROUP_CREATE",
        &format!("group:{}", payload.groupname),
        payload.dry_run,
        res.success,
        &format!("Criação do grupo '{}'", payload.groupname),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o grupo '{}' seria criado no Active Directory", payload.groupname)
                } else {
                    format!("Grupo '{}' criado com sucesso", payload.groupname)
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
                message: format!("Falha ao criar grupo: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_group(
    _operator: crate::auth::Administrator,
    Path(groupname): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    let lower = groupname.to_lowercase();
    if PROTECTED_GROUPS.contains(&lower.as_str()) {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: format!("Operação bloqueada: o grupo de segurança estrutural '{}' não pode ser excluído", groupname),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let details = run_cmd_dry(&format!("samba-tool group show {}", shell_quote(&groupname)), sudo, false);
    let structural = details.stdout.lines().any(|line| {
        let lower = line.to_lowercase();
        lower == "iscriticalsystemobject: true" || (lower.starts_with("objectsid: s-1-5-32-"))
    });
    if !details.success || structural {
        return (StatusCode::FORBIDDEN, Json(ApiResponse {
            success: false, message: "Grupo estrutural protegido ou consulta do grupo falhou.".into(),
            data: None, dry_run: q.dry_run, correlation_id: None,
        }));
    }
    let cmd = format!("samba-tool group delete {}", shell_quote(&groupname));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "GROUP_DELETE",
        &format!("group:{}", groupname),
        q.dry_run,
        res.success,
        &format!("Exclusão do grupo '{}'", groupname),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o grupo '{}' seria excluído do Active Directory", groupname)
                } else {
                    format!("Grupo '{}' excluído com sucesso", groupname)
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
                message: format!("Falha ao excluir grupo: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn add_group_member(
    _operator: crate::auth::Administrator,
    Path(groupname): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<GroupMemberRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!(
        "samba-tool group addmembers {} {}",
        shell_quote(&groupname),
        shell_quote(&payload.username)
    );
    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "GROUP_ADD_MEMBER",
        &format!("group:{}:user:{}", groupname, payload.username),
        payload.dry_run,
        res.success,
        &format!("Inclusão de '{}' no grupo '{}'", payload.username, groupname),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Usuário '{}' seria adicionado ao grupo '{}'", payload.username, groupname)
                } else {
                    format!("Usuário '{}' adicionado ao grupo '{}'", payload.username, groupname)
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
                message: format!("Falha ao adicionar membro: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn remove_group_member(
    _operator: crate::auth::Administrator,
    Path((groupname, username)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!(
        "samba-tool group removemembers {} {}",
        shell_quote(&groupname),
        shell_quote(&username)
    );
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "GROUP_REMOVE_MEMBER",
        &format!("group:{}:user:{}", groupname, username),
        q.dry_run,
        res.success,
        &format!("Remoção de '{}' do grupo '{}'", username, groupname),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Usuário '{}' seria removido do grupo '{}'", username, groupname)
                } else {
                    format!("Usuário '{}' removido do grupo '{}'", username, groupname)
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
                message: format!("Falha ao remover membro: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}
