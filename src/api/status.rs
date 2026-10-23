use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, check_service_active};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NtpInfo {
    pub active: bool,
    pub stratum: u32,
    pub reference_id: String,
    pub offset: String,
    pub leap_status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusResponse {
    pub ad_configured: bool,
    pub realm: String,
    pub workgroup: String,
    pub netbios_name: String,
    pub functional_level_forest: String,
    pub functional_level_domain: String,
    pub dns_forwarder: String,
    pub samba_active: bool,
    pub named_active: bool,
    pub chrony_active: bool,
    pub ntp: NtpInfo,
    pub users_count: usize,
    pub groups_count: usize,
    pub computers_count: usize,
    pub zones_count: usize,
    pub hostname: String,
}

pub async fn get_status(State(config): State<Arc<AppConfig>>) -> Json<StatusResponse> {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let smb_conf_path = "/etc/samba/smb.conf";
    let smb_content = fs::read_to_string(smb_conf_path).unwrap_or_default();
    let ad_configured = smb_content.contains("server role = active directory domain controller")
        || smb_content.contains("server role = active directory");

    let mut realm = String::new();
    let mut workgroup = String::new();
    let mut netbios_name = String::new();
    let mut dns_forwarder = String::new();

    for line in smb_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            match key.as_str() {
                "realm" => realm = val,
                "workgroup" => workgroup = val,
                "netbios name" => netbios_name = val,
                "dns forwarder" => dns_forwarder = val,
                _ => {}
            }
        }
    }

    let mut forest_level = "2016".to_string();
    let mut domain_level = "2016".to_string();
    if ad_configured {
        let level_cmd = "samba-tool domain level show";
        let res = run_safe_cmd(level_cmd, sudo);
        for line in res.stdout.lines() {
            if line.contains("Forest function level:") {
                if let Some((_, v)) = line.split_once(':') {
                    forest_level = v.trim().to_string();
                }
            } else if line.contains("Domain function level:") {
                if let Some((_, v)) = line.split_once(':') {
                    domain_level = v.trim().to_string();
                }
            }
        }
    }

    let samba_active = check_service_active("samba", sudo) 
        || check_service_active("samba-dc", sudo) 
        || check_service_active("samba-ad-dc", sudo);
    let named_active = check_service_active("named", sudo);
    let chrony_active = check_service_active("chronyd", sudo);

    // NTP tracking
    let mut ntp = NtpInfo {
        active: chrony_active,
        stratum: 0,
        reference_id: "Unknown".to_string(),
        offset: "0 ms".to_string(),
        leap_status: "Normal".to_string(),
    };

    if chrony_active {
        let chrony_res = run_safe_cmd("chronyc tracking", sudo);
        for line in chrony_res.stdout.lines() {
            if line.starts_with("Reference ID") {
                if let Some((_, v)) = line.split_once(':') {
                    ntp.reference_id = v.trim().to_string();
                }
            } else if line.starts_with("Stratum") {
                if let Some((_, v)) = line.split_once(':') {
                    ntp.stratum = v.trim().parse().unwrap_or(0);
                }
            } else if line.starts_with("Last offset") {
                if let Some((_, v)) = line.split_once(':') {
                    ntp.offset = v.trim().to_string();
                }
            } else if line.starts_with("Leap status") {
                if let Some((_, v)) = line.split_once(':') {
                    ntp.leap_status = v.trim().to_string();
                }
            }
        }
    }

    let mut users_count = 0;
    let mut groups_count = 0;
    let mut computers_count = 0;
    let mut zones_count = 0;

    if ad_configured && samba_active {
        let u_res = run_safe_cmd("samba-tool user list", sudo);
        users_count = u_res.stdout.lines().filter(|l| !l.trim().is_empty()).count();

        let g_res = run_safe_cmd("samba-tool group list", sudo);
        groups_count = g_res.stdout.lines().filter(|l| !l.trim().is_empty()).count();

        let c_res = run_safe_cmd("samba-tool computer list", sudo);
        computers_count = c_res.stdout.lines().filter(|l| !l.trim().is_empty()).count();

        let z_cmd = format!("samba-tool dns zonelist 127.0.0.1 -U administrator --password='{}'", admin_pass);
        let z_res = run_safe_cmd(&z_cmd, sudo);
        for line in z_res.stdout.lines() {
            if line.contains("zone(s) found") {
                if let Some(num_str) = line.split_whitespace().next() {
                    zones_count = num_str.parse().unwrap_or(0);
                }
            }
        }
    }

    let host_res = run_safe_cmd("hostname -f 2>/dev/null || hostname", sudo);
    let hostname = host_res.stdout.trim().to_string();

    Json(StatusResponse {
        ad_configured,
        realm,
        workgroup,
        netbios_name,
        functional_level_forest: forest_level,
        functional_level_domain: domain_level,
        dns_forwarder,
        samba_active,
        named_active,
        chrony_active,
        ntp,
        users_count,
        groups_count,
        computers_count,
        zones_count,
        hostname,
    })
}
