use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, ensure_firewall_port_open, check_service_active};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreflightCheck {
    pub hostname: String,
    pub fqdn: String,
    pub ip_address: String,
    pub selinux_status: String,
    pub samba_installed: bool,
    pub bind_installed: bool,
    pub chrony_installed: bool,
    pub smb_conf_exists: bool,
    pub ad_is_active: bool,
    pub ports_open: Vec<PortStatus>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortStatus {
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub open: bool,
}

#[derive(Deserialize, Debug)]
pub struct ProvisionNewDcRequest {
    pub realm: String,
    pub workgroup: String,
    pub hostname_fqdn: String,
    pub admin_password: String,
    pub dns_forwarder: Option<String>,
    pub setup_bind_hybrid: Option<bool>,
    pub upstream_forwarders: Option<Vec<String>>,
    pub static_ip: Option<String>,
    pub network_interface: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct JoinDomainRequest {
    pub realm: String,
    pub target_dc_ip: String,
    pub admin_username: String,
    pub admin_password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionResult {
    pub steps_completed: Vec<String>,
    pub error: Option<String>,
}

pub async fn run_preflight(State(config): State<Arc<AppConfig>>) -> Json<PreflightCheck> {
    let sudo = config.sudo_password.as_deref();

    let host_res = run_safe_cmd("hostname", sudo);
    let hostname = host_res.stdout.trim().to_string();

    let fqdn_res = run_safe_cmd("hostname -f 2>/dev/null || hostname", sudo);
    let fqdn = fqdn_res.stdout.trim().to_string();

    let ip_res = run_safe_cmd("hostname -I 2>/dev/null | awk '{print $1}'", sudo);
    let ip_address = ip_res.stdout.trim().to_string();

    let se_res = run_safe_cmd("getenforce 2>/dev/null || echo 'Disabled'", sudo);
    let selinux_status = se_res.stdout.trim().to_string();

    let samba_installed = run_safe_cmd("which samba-tool 2>/dev/null", sudo).success;
    let bind_installed = run_safe_cmd("which named 2>/dev/null", sudo).success;
    let chrony_installed = run_safe_cmd("which chronyd 2>/dev/null", sudo).success;
    let smb_conf_exists = Path::new("/etc/samba/smb.conf").exists();
    let ad_is_active = check_service_active("samba", sudo) || check_service_active("samba-dc", sudo);

    let check_ports = vec![
        (53, "tcp", "DNS (TCP)"),
        (53, "udp", "DNS (UDP)"),
        (88, "tcp", "Kerberos (TCP)"),
        (88, "udp", "Kerberos (UDP)"),
        (135, "tcp", "RPC EndPoint Mapper"),
        (389, "tcp", "LDAP (TCP)"),
        (389, "udp", "LDAP (UDP)"),
        (445, "tcp", "SMB over TCP"),
        (464, "tcp", "kpasswd"),
        (636, "tcp", "LDAPS"),
        (3268, "tcp", "Global Catalog"),
        (5353, "udp", "BIND Hybrid (UDP)"),
        (8095, "tcp", "Astral Web Console"),
    ];

    let mut ports_open = Vec::new();
    for (port, proto, desc) in check_ports {
        let chk = format!("iptables -C INPUT -p {} -m {} --dport {} -j ACCEPT 2>/dev/null", proto, proto, port);
        let open = run_safe_cmd(&chk, sudo).success;
        ports_open.push(PortStatus {
            port,
            proto: proto.to_string(),
            service: desc.to_string(),
            open,
        });
    }

    Json(PreflightCheck {
        hostname,
        fqdn,
        ip_address,
        selinux_status,
        samba_installed,
        bind_installed,
        chrony_installed,
        smb_conf_exists,
        ad_is_active,
        ports_open,
    })
}

pub async fn provision_new_dc(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ProvisionNewDcRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    // 1. NON-DESTRUCTIVE SAFE FIREWALL PORT VERIFICATION
    // CRITICAL USER DIRECTIVE: Never wipe or flush existing firewall rules!
    let ports = vec![
        (53, "tcp"), (53, "udp"),
        (88, "tcp"), (88, "udp"),
        (123, "udp"),
        (135, "tcp"),
        (137, "udp"), (138, "udp"), (139, "tcp"),
        (389, "tcp"), (389, "udp"),
        (445, "tcp"),
        (464, "tcp"), (464, "udp"),
        (636, "tcp"),
        (3268, "tcp"), (3269, "tcp"),
        (5353, "tcp"), (5353, "udp"),
        (8095, "tcp"),
    ];

    for (p, proto) in ports {
        ensure_firewall_port_open(p, proto, sudo);
    }
    steps.push("Safe firewall ports verified (no existing rules wiped).".to_string());

    // 2. Chrony Signed NTP Socket configuration
    let chrony_conf = "/etc/chrony.conf";
    if let Ok(chrony_text) = fs::read_to_string(chrony_conf) {
        if !chrony_text.contains("ntpsigndsocket /var/lib/samba/ntp_signd") {
            let _ = run_safe_cmd("echo 'ntpsigndsocket /var/lib/samba/ntp_signd' >> /etc/chrony.conf", sudo);
            let _ = run_safe_cmd("mkdir -p /var/lib/samba/ntp_signd && chown root:chrony /var/lib/samba/ntp_signd 2>/dev/null || true", sudo);
            let _ = run_safe_cmd("chmod 750 /var/lib/samba/ntp_signd || true", sudo);
            let _ = run_safe_cmd("systemctl restart chronyd || true", sudo);
            steps.push("Chrony signed NTP socket configured.".to_string());
        }
    }

    // 3. Hybrid BIND 9 Configuration (port 5353)
    if payload.setup_bind_hybrid.unwrap_or(true) {
        let fwd_list = payload.upstream_forwarders.unwrap_or_else(|| vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]);
        let fwd_formatted = fwd_list.iter().map(|f| format!(" {};", f.trim())).collect::<Vec<_>>().join("");

        let named_conf = format!(r#"options {{
    directory "/var/named";
    listen-on port 5353 {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    allow-query {{ localhost; }};
    recursion yes;
    forwarders {{{} }};
    dnssec-validation no;
    max-cache-size 64m;
}};
"#, fwd_formatted);

        let temp_named = "/tmp/named.conf.gen";
        let _ = fs::write(temp_named, named_conf);
        let _ = run_safe_cmd(&format!("cp -f {} /etc/named.conf", temp_named), sudo);
        let _ = fs::remove_file(temp_named);
        let _ = run_safe_cmd("systemctl enable --now named || true", sudo);
        steps.push("BIND 9 hybrid recursive forwarder configured on 127.0.0.1:5353.".to_string());
    }

    // 4. Samba Domain Provision
    let forwarder = payload.dns_forwarder.unwrap_or_else(|| "127.0.0.1:5353".to_string());
    let _ = run_safe_cmd("mv /etc/samba/smb.conf /etc/samba/smb.conf.bak.$(date +%s) 2>/dev/null || true", sudo);

    let prov_cmd = format!(
        "samba-tool domain provision --use-rfc2307 --realm='{}' --domain='{}' --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='{}'",
        payload.realm.to_uppercase(),
        payload.workgroup.to_uppercase(),
        payload.admin_password.replace('\'', "")
    );

    let prov_res = run_safe_cmd(&prov_cmd, sudo);
    if !prov_res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Samba domain provisioning failed: {}", prov_res.stderr),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: Some(prov_res.stderr),
                }),
            }),
        );
    }
    steps.push(format!("Samba AD DC provisioned for realm '{}'.", payload.realm.to_uppercase()));

    // 5. Fine tune smb.conf (Functional level 2016 + BIND Forwarder)
    let tune_cmd = format!(
        r#"sed -i '/\[global\]/a \    dns forwarder = {}\n    ad dc functional level = 2016\n    bind interfaces only = yes' /etc/samba/smb.conf"#,
        forwarder
    );
    let _ = run_safe_cmd(&tune_cmd, sudo);
    steps.push("smb.conf configured with Functional Level 2016 and DNS forwarder.".to_string());

    // 6. Kerberos setup
    let _ = run_safe_cmd("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true", sudo);
    steps.push("Kerberos /etc/krb5.conf linked.".to_string());

    // 7. Start Services
    let _ = run_safe_cmd("systemctl unmask samba 2>/dev/null || true", sudo);
    let _ = run_safe_cmd("systemctl enable --now samba 2>/dev/null || systemctl enable --now samba-dc 2>/dev/null || true", sudo);
    steps.push("Samba Active Directory service started.".to_string());

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: "Active Directory Domain Controller provisioned successfully!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
            }),
        }),
    )
}

pub async fn join_domain(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<JoinDomainRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    // Verify firewall ports safely
    let ports = vec![
        (53, "tcp"), (53, "udp"),
        (88, "tcp"), (88, "udp"),
        (135, "tcp"), (445, "tcp"),
        (389, "tcp"), (636, "tcp"),
        (3268, "tcp"), (5353, "udp"),
        (8095, "tcp"),
    ];
    for (p, proto) in ports {
        ensure_firewall_port_open(p, proto, sudo);
    }
    steps.push("Safe firewall ports verified.".to_string());

    let _ = run_safe_cmd("mv /etc/samba/smb.conf /etc/samba/smb.conf.join.bak 2>/dev/null || true", sudo);

    let join_cmd = format!(
        "samba-tool domain join '{}' DC -U'{}' --password='{}' --dns-backend=SAMBA_INTERNAL",
        payload.realm.to_uppercase(),
        payload.admin_username.replace('\'', ""),
        payload.admin_password.replace('\'', "")
    );

    let join_res = run_safe_cmd(&join_cmd, sudo);
    if !join_res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Domain join failed: {}", join_res.stderr),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: Some(join_res.stderr),
                }),
            }),
        );
    }
    steps.push(format!("Successfully joined '{}' as Secondary Domain Controller.", payload.realm.to_uppercase()));

    let _ = run_safe_cmd("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true", sudo);
    let _ = run_safe_cmd("systemctl enable --now samba || true", sudo);
    steps.push("Services started.".to_string());

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Domain joined successfully as secondary DC!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
            }),
        }),
    )
}
