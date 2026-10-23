use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, sanitize_arg};
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OuItem {
    pub dn: String,
    pub name: String,
    pub parent_dn: String,
    pub description: Option<String>,
    pub is_system: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OuObjectItem {
    pub name: String,
    pub object_type: String, // "User", "Computer", "Group", "OU", "Other"
    pub dn: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateOuRequest {
    pub name: String,
    pub parent_dn: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn list_ous(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<OuItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool ou list", sudo, false);

    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar Unidades Organizacionais: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let mut ous = Vec::new();
    for line in res.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let dn = trimmed.to_string();
        let name = dn.split(',').next().unwrap_or(&dn).trim_start_matches("OU=").to_string();
        let parent_dn = dn.split_once(',').map(|(_, rest)| rest.to_string()).unwrap_or_default();
        let is_system = name.to_uppercase() == "DOMAIN CONTROLLERS";

        ous.push(OuItem {
            dn,
            name,
            parent_dn,
            description: None,
            is_system,
        });
    }

    ous.sort_by(|a, b| a.name.cmp(&b.name));

    Json(ApiResponse {
        success: true,
        message: format!("Recuperadas {} Unidades Organizacionais", ous.len()),
        data: Some(ous),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_ou(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateOuRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let ou_name = payload.name.trim();

    if ou_name.is_empty() || ou_name.contains(',') || ou_name.contains('=') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome da OU inválido".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    // Se parent_dn não for fornecido, obtém o base DN do domínio
    let full_ou_dn = if let Some(parent) = payload.parent_dn.filter(|p| !p.trim().is_empty()) {
        format!("OU={},{}", sanitize_arg(ou_name), parent.trim())
    } else {
        // Detecta base DN a partir do realm
        let ldb_res = run_cmd_dry("samba-tool domain info 127.0.0.1 2>/dev/null | grep -i 'Domain' | awk '{print $NF}'", sudo, false);
        let domain = ldb_res.stdout.trim().to_lowercase();
        let default_base_dn = if !domain.is_empty() && domain.contains('.') {
            domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
        } else {
            "DC=srvcloud,DC=cloud".to_string()
        };
        format!("OU={},{}", sanitize_arg(ou_name), default_base_dn)
    };

    let mut cmd = format!("samba-tool ou create '{}'", full_ou_dn);
    if let Some(desc) = payload.description.as_deref().filter(|d| !d.trim().is_empty()) {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(desc)));
    }

    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "OU_CREATE",
        &format!("ou:{}", full_ou_dn),
        payload.dry_run,
        res.success,
        &format!("Criação da Unidade Organizacional '{}'", full_ou_dn),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] A OU '{}' seria criada no Active Directory", full_ou_dn)
                } else {
                    format!("Unidade Organizacional '{}' criada com sucesso", full_ou_dn)
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
                message: format!("Falha ao criar Unidade Organizacional: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_ou(
    Path(ou_dn): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    // TRAVA DE SEGURANÇA: Jamais permitir exclusão de Domain Controllers
    let up = ou_dn.to_uppercase();
    if up.contains("DOMAIN CONTROLLERS") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "Não é permitido excluir a OU de sistema 'Domain Controllers'".to_string(),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool ou delete '{}'", sanitize_arg(&ou_dn));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "OU_DELETE",
        &format!("ou:{}", ou_dn),
        q.dry_run,
        res.success,
        &format!("Exclusão da Unidade Organizacional '{}'", ou_dn),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Unidade Organizacional '{}' excluída com sucesso", ou_dn),
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
                message: format!("Falha ao excluir Unidade Organizacional: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn list_ou_objects(
    Path(ou_dn): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<OuObjectItem>>> {
    let sudo = config.sudo_password.as_deref();
    let cmd = format!("samba-tool ou listobjects '{}'", sanitize_arg(&ou_dn));
    let res = run_cmd_dry(&cmd, sudo, false);

    let mut objects = Vec::new();
    if res.success {
        for line in res.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let dn = trimmed.to_string();
            let first_part = dn.split(',').next().unwrap_or(&dn);
            let (obj_type, name) = if first_part.starts_with("CN=") {
                let clean = first_part.trim_start_matches("CN=");
                if clean.ends_with('$') || clean.to_uppercase().contains("DC") {
                    ("Computer".to_string(), clean.to_string())
                } else {
                    ("User/Group".to_string(), clean.to_string())
                }
            } else if first_part.starts_with("OU=") {
                ("OU".to_string(), first_part.trim_start_matches("OU=").to_string())
            } else {
                ("Object".to_string(), first_part.to_string())
            };

            objects.push(OuObjectItem {
                name,
                object_type: obj_type,
                dn,
            });
        }
    }

    Json(ApiResponse {
        success: true,
        message: format!("Recuperados {} objetos dentro da OU", objects.len()),
        data: Some(objects),
        dry_run: false,
        correlation_id: None,
    })
}
