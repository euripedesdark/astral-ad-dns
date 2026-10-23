pub mod terminal;
pub mod status;
pub mod users;
pub mod groups;
pub mod computers;
pub mod ou;
pub mod gpo;
pub mod dns;
pub mod bind;
pub mod health;
pub mod backup;
pub mod provision;
pub mod firewall;
pub mod diagnostics;
pub mod audit;

use axum::{
    routing::{get, post, delete},
    Router,
};
use std::sync::Arc;
use crate::config::AppConfig;

pub fn create_api_router(config: Arc<AppConfig>) -> Router {
    Router::new()
        // Autenticação Unificada (OAuth2 / Samba AD / Linux Sudo / Postgres Superuser)
        .route("/api/auth/login", post(crate::auth::login_handler))
        .route("/api/auth/me", get(crate::auth::me_handler))
        .route("/api/auth/logout", post(crate::auth::logout_handler))
        .route("/api/auth/providers", get(crate::auth::providers_handler))

        
        // Terminal Operacional para Intervenções Pontuais (Restrito a AD e Linux Sudo)
        .route("/api/terminal/status", get(terminal::get_terminal_status))
        .route("/api/terminal/exec", post(terminal::exec_terminal_cmd))

        // Status & Overview
        .route("/api/status", get(status::get_status))
        .route("/api/checks", get(status::run_quick_checks))

        // Diagnóstico Completo de Conexão e Dependências
        .route("/api/diagnostics", get(diagnostics::run_diagnostics))

        // Histórico Operacional e Auditoria
        .route("/api/audit", get(audit::list_audit_events).delete(audit::clear_audit_events))

        // Gerenciamento Seguro de Firewall (Portas do AD)
        .route("/api/firewall", get(firewall::get_firewall_status))
        .route("/api/firewall/open", post(firewall::open_firewall_ports))
        .route("/api/firewall/auto-reconcile", post(firewall::auto_reconcile_ports))
        .route("/api/firewall/migration/status", get(firewall::get_migration_status))
        .route("/api/firewall/migration/migrate", post(firewall::migrate_firewall))

        // Users
        .route("/api/users", get(users::list_users).post(users::create_user))
        .route("/api/users/{username}", delete(users::delete_user))
        .route("/api/users/{username}/properties", get(users::get_user_properties))
        .route("/api/users/{username}/groups", get(users::get_user_groups).put(users::update_user_groups).post(users::update_user_groups))
        .route("/api/users/{username}/groups/{groupname}", post(users::add_user_to_group).delete(users::remove_user_from_group))
        .route("/api/users/{username}/password", post(users::set_password))
        .route("/api/users/{username}/enable", post(users::enable_user))
        .route("/api/users/{username}/disable", post(users::disable_user))

        // Groups
        .route("/api/groups", get(groups::list_groups).post(groups::create_group))
        .route("/api/groups/{groupname}", delete(groups::delete_group))
        .route("/api/groups/{groupname}/members", get(groups::get_group_members).post(groups::add_group_member))
        .route("/api/groups/{groupname}/members/{username}", delete(groups::remove_group_member))

        // Computers
        .route("/api/computers", get(computers::list_computers).post(computers::create_computer))
        .route("/api/computers/{computername}", delete(computers::delete_computer))
        .route("/api/computers/{computername}/properties", get(computers::get_computer_properties))

        // Unidades Organizacionais (OU) & Objetos
        .route("/api/ou", get(ou::list_ous).post(ou::create_ou))
        .route("/api/ou/{ou_dn}", delete(ou::delete_ou))
        .route("/api/ou/{ou_dn}/objects", get(ou::list_ou_objects))

        // Diretivas de Grupo (GPO)
        .route("/api/gpo", get(gpo::list_gpos).post(gpo::create_gpo))
        .route("/api/gpo/{guid}", delete(gpo::delete_gpo))
        .route("/api/gpo/{guid}/link", post(gpo::link_gpo))
        .route("/api/gpo/{guid}/link/{container_dn}", delete(gpo::unlink_gpo))

        // DNS
        .route("/api/dns/zones", get(dns::list_zones).post(dns::create_zone))
        .route("/api/dns/zones/{zone}", delete(dns::delete_zone))
        .route("/api/dns/zones/{zone}/records", get(dns::query_records).post(dns::add_record).delete(dns::delete_record))

        // BIND 9 Hybrid DNS
        .route("/api/bind/status", get(bind::get_bind_status))
        .route("/api/bind/forwarders", post(bind::update_forwarders))
        .route("/api/bind/test", post(bind::test_query))
        .route("/api/bind/logs", get(bind::get_bind_logs))
        .route("/api/bind/service/{action}", post(bind::service_action))

        // Health, Replication & SYSVOL
        .route("/api/health/drs", get(health::get_drs_status))
        .route("/api/health/dbcheck", post(health::run_dbcheck))
        .route("/api/health/sysvolcheck", post(health::run_sysvolcheck))
        .route("/api/health/sysvolreset", post(health::run_sysvolreset))
        .route("/api/health/sysvol-script", get(health::get_powershell_sync_script))

        // Backups
        .route("/api/backups", get(backup::list_backups).post(backup::create_backup))
        .route("/api/backups/restore", post(backup::restore_backup))
        .route("/api/backups/{filename}", delete(backup::delete_backup))

        // Provisioning & DC Join Wizard + Advanced PKI/Schema + AD DNS Sync
        .route("/api/provision/preflight", get(provision::run_preflight))
        .route("/api/provision/new-dc", post(provision::provision_new_dc))
        .route("/api/provision/join-dc", post(provision::join_domain))
        .route("/api/provision/reset-samba", post(provision::reset_samba_state))
        .route("/api/provision/verify-ad-dns", get(provision::verify_ad_dns_status))
        .route("/api/provision/sync-ad-dns", post(provision::sync_ad_dns_dc))
        .route("/api/provision/upgrade-schema", post(provision::upgrade_schema_and_levels))
        .route("/api/provision/fix-dns-partitions", post(provision::fix_dns_partitions))
        .route("/api/provision/step-ca", post(provision::setup_step_ca))
        .route("/api/provision/reverse-zone", post(provision::configure_reverse_zone))

        .with_state(config)
}
