pub mod status;
pub mod users;
pub mod groups;
pub mod computers;
pub mod dns;
pub mod bind;
pub mod health;
pub mod backup;
pub mod provision;

use axum::{
    routing::{get, post, delete},
    Router,
};
use std::sync::Arc;
use crate::config::AppConfig;

pub fn create_api_router(config: Arc<AppConfig>) -> Router {
    Router::new()
        // Status & Overview
        .route("/api/status", get(status::get_status))

        // Users
        .route("/api/users", get(users::list_users).post(users::create_user))
        .route("/api/users/{username}", delete(users::delete_user))
        .route("/api/users/{username}/groups", get(users::get_user_groups))
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

        // Provisioning & DC Join Wizard
        .route("/api/provision/preflight", get(provision::run_preflight))
        .route("/api/provision/new-dc", post(provision::provision_new_dc))
        .route("/api/provision/join-dc", post(provision::join_domain))

        .with_state(config)
}
