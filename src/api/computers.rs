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
pub struct ComputerItem {
    pub name: String,
    pub is_dc: bool,
}

#[derive(Deserialize, Debug)]
pub struct CreateComputerRequest {
    pub computername: String,
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn list_computers(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<ComputerItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool computer list", sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar computadores: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
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
        message: format!("Recuperados {} computadores", computers.len()),
        data: Some(computers),
        dry_run: false,
        correlation_id: None,
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
                message: "Nome do computador é obrigatório".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let mut cmd = format!("samba-tool computer create '{}'", sanitize_arg(&payload.computername));
    if let Some(desc) = payload.description {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(&desc)));
    }

    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "COMPUTER_CREATE",
        &format!("computer:{}", payload.computername),
        payload.dry_run,
        res.success,
        &format!("Criação de computador '{}'", payload.computername),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o computador '{}' seria adicionado ao domínio", payload.computername)
                } else {
                    format!("Computador '{}' criado com sucesso", payload.computername)
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
                message: format!("Falha ao criar computador: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_computer(
    Path(computername): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    // TRAVA DE SEGURANÇA: Não permitir exclusão acidental do controlador de domínio principal!
    let upper = computername.to_uppercase();
    if upper.contains("DC-ERP") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: format!("Operação bloqueada: '{}' é o Controlador de Domínio (DC) do cluster e não pode ser excluído", computername),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("samba-tool computer delete '{}'", sanitize_arg(&computername));
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "COMPUTER_DELETE",
        &format!("computer:{}", computername),
        q.dry_run,
        res.success,
        &format!("Exclusão do computador '{}'", computername),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o computador '{}' seria removido do Active Directory", computername)
                } else {
                    format!("Computador '{}' excluído com sucesso", computername)
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
                message: format!("Falha ao excluir computador: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}
