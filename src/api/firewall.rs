use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{samba_ad_ports, check_port_open, open_port_safe, PortRule, CommandResult};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallPortItem {
    pub proto: String,
    pub port: String,
    pub label: String,
    pub is_open: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallStatusResponse {
    pub all_required_open: bool,
    pub total_ports: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub ports: Vec<FirewallPortItem>,
}

#[derive(Deserialize, Debug)]
pub struct OpenPortsRequest {
    pub ports: Vec<PortRule>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn get_firewall_status(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<FirewallStatusResponse>> {
    let sudo = config.sudo_password.as_deref();
    let rules = samba_ad_ports();

    let mut items = Vec::new();
    let mut open_count = 0;

    for r in rules {
        let is_open = check_port_open(&r.proto, &r.port, sudo);
        if is_open {
            open_count += 1;
        }
        items.push(FirewallPortItem {
            proto: r.proto,
            port: r.port,
            label: r.label,
            is_open,
        });
    }

    let total = items.len();
    let closed = total - open_count;

    Json(ApiResponse {
        success: true,
        message: format!("Status do firewall: {}/{} portas do AD abertas", open_count, total),
        data: Some(FirewallStatusResponse {
            all_required_open: closed == 0,
            total_ports: total,
            open_count,
            closed_count: closed,
            ports: items,
        }),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn open_firewall_ports(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<OpenPortsRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<CommandResult>>>) {
    let sudo = config.sudo_password.as_deref();
    let mut results = Vec::new();
    let mut success_all = true;

    for rule in &payload.ports {
        let res = open_port_safe(rule, sudo, payload.dry_run);
        if !res.success {
            success_all = false;
        }
        results.push(res);
    }

    let target_desc = format!("{} portas (ex: {:?})", payload.ports.len(), payload.ports.first().map(|p| &p.port));
    let details = if payload.dry_run {
        format!("[SIMULAÇÃO] Simulação de abertura de {} portas do Samba AD", payload.ports.len())
    } else {
        format!("Abertura de {} portas do Samba AD no iptables (modo seguro)", payload.ports.len())
    };

    let evt_id = config.audit.record(
        "admin",
        None,
        "FIREWALL_PORT_OPEN",
        &target_desc,
        payload.dry_run,
        success_all,
        &details,
    );

    let msg = if payload.dry_run {
        format!("[SIMULAÇÃO] Plano de abertura de {} portas gerado", results.len())
    } else if success_all {
        format!("{} portas do Samba AD processadas com sucesso", results.len())
    } else {
        "Algumas portas apresentaram falha ao serem processadas".to_string()
    };

    (
        if success_all { StatusCode::OK } else { StatusCode::BAD_REQUEST },
        Json(ApiResponse {
            success: success_all,
            message: msg,
            data: Some(results),
            dry_run: payload.dry_run,
            correlation_id: Some(evt_id),
        }),
    )
}
