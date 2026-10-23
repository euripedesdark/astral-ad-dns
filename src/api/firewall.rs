use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{
    detect_enabled_services, required_ports_for_services, check_port_open, open_port_safe,
    auto_reconcile_firewall_ports, PortRule, CommandResult, EnabledServices, FirewallReconcileReport,
};
use crate::system::firewall_migration::{
    detect_firewall_managers, execute_migration_to_iptables, MigrationStatusResponse,
    MigrationResult,
};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallPortItem {
    pub proto: String,
    pub port: String,
    pub label: String,
    pub is_open: bool,
    pub is_listening: bool,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallStatusResponse {
    pub all_required_open: bool,
    pub total_ports: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub services: EnabledServices,
    pub ports: Vec<FirewallPortItem>,
}

#[derive(Deserialize, Debug)]
pub struct OpenPortsRequest {
    pub ports: Vec<PortRule>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct AutoReconcileRequest {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct MigrateFirewallRequest {
    pub manager: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn get_firewall_status(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<FirewallStatusResponse>> {
    let sudo = config.sudo_password.as_deref();
    let services = detect_enabled_services(sudo);
    let rules = required_ports_for_services(&services);

    let ss_out = crate::system::run_safe_cmd("ss -tuln 2>/dev/null", sudo).stdout;

    let mut items = Vec::new();
    let mut open_count = 0;

    for r in rules {
        let is_open = check_port_open(&r.proto, &r.port, sudo);
        let clean_port = r.port.split(':').next().unwrap_or(&r.port);
        let is_listening = ss_out.contains(&format!(":{}", clean_port));

        if is_open {
            open_count += 1;
        }

        items.push(FirewallPortItem {
            proto: r.proto,
            port: r.port,
            label: r.label,
            is_open,
            is_listening,
            status: if is_open { "OPEN".to_string() } else { "CLOSED".to_string() },
        });
    }

    let total = items.len();
    let closed = total - open_count;

    Json(ApiResponse {
        success: true,
        message: format!("Status do firewall: {}/{} portas ativas abertas", open_count, total),
        data: Some(FirewallStatusResponse {
            all_required_open: closed == 0,
            total_ports: total,
            open_count,
            closed_count: closed,
            services,
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
        format!("[SIMULAÇÃO] Simulação de abertura de {} portas no firewall", payload.ports.len())
    } else {
        format!("Abertura de {} portas no iptables (modo seguro)", payload.ports.len())
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
        format!("{} portas processadas com sucesso", results.len())
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

pub async fn auto_reconcile_ports(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<AutoReconcileRequest>,
) -> (StatusCode, Json<ApiResponse<FirewallReconcileReport>>) {
    let sudo = config.sudo_password.as_deref();
    let report = auto_reconcile_firewall_ports(sudo, payload.dry_run);

    let details = format!(
        "Reconciliação automática de portas: total={}, abertas={}, corrigidas={}, falhas={}",
        report.total_ports, report.open_count, report.corrected_count, report.failed_count
    );

    let evt_id = config.audit.record(
        "system",
        None,
        "FIREWALL_AUTO_RECONCILE",
        "all_services",
        payload.dry_run,
        report.failed_count == 0,
        &details,
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: details,
            data: Some(report),
            dry_run: payload.dry_run,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn get_migration_status(
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<MigrationStatusResponse>> {
    let sudo = config.sudo_password.as_deref();
    let (primary, foreign) = detect_firewall_managers(sudo);

    let ipt_active = crate::system::check_service_active("iptables", sudo);
    let ip6_active = crate::system::check_service_active("ip6tables", sudo);
    let ipt_installed = std::path::Path::new("/usr/sbin/iptables").exists();

    // Lê backups disponíveis em /var/backups/astral-ad-dns/firewall
    let mut available_backups = Vec::new();
    let backup_root = std::path::Path::new("/var/backups/astral-ad-dns/firewall");
    if let Ok(entries) = std::fs::read_dir(backup_root) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.starts_with("backup_") {
                    available_backups.push(file_name);
                }
            }
        }
    }
    available_backups.sort();
    available_backups.reverse();

    let migration_needed = !foreign.is_empty();

    Json(ApiResponse {
        success: true,
        message: "Status dos gerenciadores de firewall e migração".to_string(),
        data: Some(MigrationStatusResponse {
            current_active_manager: primary,
            other_managers_detected: foreign,
            migration_needed,
            iptables_services_installed: ipt_installed,
            iptables_active: ipt_active,
            ip6tables_active: ip6_active,
            last_backup: None,
            available_backups,
        }),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn migrate_firewall(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<MigrateFirewallRequest>,
) -> (StatusCode, Json<ApiResponse<MigrationResult>>) {
    let sudo = config.sudo_password.as_deref();
    let (_primary, foreign) = detect_firewall_managers(sudo);

    let manager_to_migrate = payload.manager.unwrap_or_else(|| {
        foreign.first().cloned().unwrap_or_else(|| "none".to_string())
    });

    if manager_to_migrate == "none" || manager_to_migrate == "iptables" {
        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "Nenhum gerenciador externo ativo detectado para migração. O sistema já opera nativamente com iptables.".to_string(),
                data: Some(MigrationResult {
                    success: true,
                    dry_run: payload.dry_run,
                    manager_migrated: "iptables".to_string(),
                    backup_dir: String::new(),
                    sha256sums_file: String::new(),
                    rules_applied_count: 0,
                    steps: vec!["Sistema já opera exclusivamente com iptables.".to_string()],
                    errors: vec![],
                }),
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let result = execute_migration_to_iptables(&manager_to_migrate, sudo, payload.dry_run);

    let details = format!(
        "Migração de firewall '{}' para iptables: success={}, steps={}, errors={}",
        manager_to_migrate, result.success, result.steps.len(), result.errors.len()
    );

    let evt_id = config.audit.record(
        "admin",
        None,
        "FIREWALL_MIGRATION",
        &manager_to_migrate,
        payload.dry_run,
        result.success,
        &details,
    );

    let status = if result.success { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR };

    (
        status,
        Json(ApiResponse {
            success: result.success,
            message: details,
            data: Some(result),
            dry_run: payload.dry_run,
            correlation_id: Some(evt_id),
        }),
    )
}
