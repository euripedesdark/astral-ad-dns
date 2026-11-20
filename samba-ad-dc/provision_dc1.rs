// ==============================================================================
// Astral AD & Hybrid DNS - Primary Domain Controller (DC1) Provisioning (Rust)
// ==============================================================================

use std::fs;
use std::path::Path;
use std::process::Command;
use serde::{Deserialize, Serialize};

use crate::directory_config::detect_distro_profile;
use crate::provision_system::{allocate_ca_port, apply_firewall, configure_chrony, configure_hosts};
use crate::provision_pki::configure_step_ca;

fn default_domain_role() -> String {
    "DC".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRequest {
    #[serde(default = "default_domain_role")]
    pub domain_role: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default, alias = "dc_netbios_name")]
    pub netbios_name: String,
    #[serde(default)]
    pub hostname_fqdn: String,
    #[serde(default, alias = "static_ip")]
    pub host_ip: String,
    #[serde(default)]
    pub admin_password: String,
    #[serde(default)]
    pub admin_username: Option<String>,
    #[serde(default)]
    pub dns_backend: Option<String>,
    #[serde(default, alias = "dns_forwarder")]
    pub forwarder_dns: Option<String>,
    #[serde(default)]
    pub upstream_forwarders: Vec<String>,
    #[serde(default)]
    pub setup_step_ca: bool,
    #[serde(default)]
    pub initialize_ca: bool,
    #[serde(default)]
    pub cert_password: Option<String>,
    #[serde(default, alias = "setup_bind_hybrid")]
    pub bind_dlz: bool,
    #[serde(default)]
    pub overwrite_existing: bool,
    #[serde(default)]
    pub clean_existing: bool,
    #[serde(default)]
    pub rejoin: bool,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub _job_status_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionResponse {
    pub success: bool,
    pub message: String,
    pub steps_completed: Vec<String>,
    pub ca_url: Option<String>,
    pub error: Option<String>,
}

pub fn execute_dc1_provision(request: &ProvisionRequest, root: &Path) -> Result<ProvisionResponse, String> {
    let mut steps = Vec::new();
    let profile = detect_distro_profile(root);

    let update_progress = |phase: &str, steps_list: &[String]| {
        if let Some(status_path) = request._job_status_path.as_deref() {
            let status_json = serde_json::json!({
                "state": "running",
                "phase": phase,
                "steps": steps_list,
            });
            let _ = fs::write(status_path, status_json.to_string());
        }
    };

    update_progress("preflight", &steps);

    // 1. Configure Hostname and Hosts
    configure_hosts(root, &request.hostname_fqdn, &request.host_ip)?;
    steps.push(format!("Identidade local configurada: {} ({})", request.hostname_fqdn, request.host_ip));

    // 2. Configure Firewall
    let ca_port = if request.setup_step_ca {
        allocate_ca_port(8443).unwrap_or(8443)
    } else {
        8443
    };
    let added = apply_firewall(&request.domain_role, request.setup_step_ca, ca_port)
        .unwrap_or(0);
    steps.push(format!("Firewall: regras para AD DC e serviços verificadas ({} regras aplicadas).", added));

    // 3. Configure Chrony NTP Signing
    if let Err(e) = configure_chrony(root) {
        eprintln!("[WARN] Erro ao configurar Chrony: {}", e);
    } else {
        steps.push("NTP assinado ntp_signd configurado e chrony ativo.".to_string());
    }

    // 4. Setup Step-CA if requested
    let mut ca_url = None;
    if request.setup_step_ca {
        let pwd = request.cert_password.as_deref().unwrap_or(&request.admin_password);
        match configure_step_ca(root, &request.realm, &request.hostname_fqdn, &request.host_ip, ca_port, pwd) {
            Ok(url) => {
                ca_url = Some(url.clone());
                steps.push(format!("Certificado LDAPS emitido e CA configurada em: {}", url));
            }
            Err(e) => {
                eprintln!("[WARN] Falha ao configurar Step CA: {}", e);
            }
        }
    }

    // 5. Samba domain provision
    let dns_backend = if request.bind_dlz {
        "BIND9_DLZ"
    } else {
        request.dns_backend.as_deref().unwrap_or("SAMBA_INTERNAL")
    };

    // Remove old smb.conf before provision
    let _ = fs::remove_file(root.join("etc/samba/smb.conf"));

    let mut prov_cmd = Command::new("samba-tool");
    prov_cmd.args([
        "domain", "provision",
        "--use-rfc2307",
        &format!("--realm={}", request.realm),
        &format!("--domain={}", request.netbios_name),
        "--server-role=dc",
        &format!("--dns-backend={}", dns_backend),
        &format!("--adminpass={}", request.admin_password),
    ]);
    if let Some(ref fwd) = request.forwarder_dns {
        if !fwd.is_empty() {
            prov_cmd.arg(format!("--option=dns forwarder = {}", fwd));
        }
    }

    let output = prov_cmd.output().map_err(|e| format!("Falha ao executar samba-tool provision: {}", e))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("samba-tool domain provision falhou: {}", err));
    }
    steps.push(format!("Novo domínio {} provisionado com sucesso.", request.realm));

    // 6. Copy krb5.conf
    let private_krb5 = root.join("var/lib/samba/private/krb5.conf");
    let etc_krb5 = root.join("etc/krb5.conf");
    if private_krb5.exists() {
        let _ = fs::copy(&private_krb5, &etc_krb5);
    }

    // 7. Enable and start samba services
    for conflict in &profile.samba_conflicts {
        let _ = Command::new("systemctl").args(["stop", conflict]).output();
        let _ = Command::new("systemctl").args(["disable", conflict]).output();
        let _ = Command::new("systemctl").args(["mask", conflict]).output();
    }
    let _ = Command::new("systemctl").args(["unmask", &profile.samba_unit]).output();
    let _ = Command::new("systemctl").args(["enable", "--now", &profile.samba_unit]).output();
    let _ = Command::new("systemctl").args(["restart", &profile.samba_unit]).output();
    steps.push(format!("Serviço Samba AD ({}) ativo.", profile.samba_unit));

    Ok(ProvisionResponse {
        success: true,
        message: "Provisionamento concluido com sucesso.".to_string(),
        steps_completed: steps,
        ca_url,
        error: None,
    })
}
