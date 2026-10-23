use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::time::Instant;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, check_service_active};
use crate::api::users::ApiResponse;

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
    pub overall_health: String, // "operational", "degraded", "unavailable"
    pub last_updated: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResultItem {
    pub name: String,
    pub command: String,
    pub ok: bool,
    pub output: String,
    pub latency_ms: u64,
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

    let overall_health = if !ad_configured {
        "not_provisioned".to_string()
    } else if !samba_active {
        "unavailable".to_string()
    } else if !named_active || !chrony_active {
        "degraded".to_string()
    } else {
        "operational".to_string()
    };

    let last_updated = chrono::Utc::now().to_rfc3339();

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
        overall_health,
        last_updated,
    })
}

/// Executa a bateria de checklist operacional recomendada pelo artigo
pub async fn run_quick_checks(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<CheckResultItem>>> {
    let sudo = config.sudo_password.as_deref();
    let smb_content = fs::read_to_string("/etc/samba/smb.conf").unwrap_or_default();
    let realm = smb_content
        .lines()
        .find(|l| l.trim().to_lowercase().starts_with("realm"))
        .and_then(|l| l.split_once('='))
        .map(|(_, v)| v.trim().to_lowercase())
        .unwrap_or_else(|| "srvcloud.cloud".to_string());

    let mut results = Vec::new();

    // 1. testparm -s
    let t0 = Instant::now();
    let r1 = run_safe_cmd("testparm -s 2>&1", sudo);
    results.push(CheckResultItem {
        name: "Validação de Configuração (testparm)".to_string(),
        command: "testparm -s".to_string(),
        ok: r1.success && !r1.stdout.contains("ERROR"),
        output: if r1.success { "Sintaxe do smb.conf válida".to_string() } else { r1.stderr },
        latency_ms: t0.elapsed().as_millis() as u64,
    });

    // 2. samba-tool dbcheck
    let t0 = Instant::now();
    let r2 = run_safe_cmd("samba-tool dbcheck --cross-ncs 2>&1", sudo);
    results.push(CheckResultItem {
        name: "Integridade da Base de Dados (dbcheck)".to_string(),
        command: "samba-tool dbcheck --cross-ncs".to_string(),
        ok: r2.success || !r2.stdout.contains("ERROR:"),
        output: if r2.success { "Base de dados íntegra".to_string() } else { r2.stdout },
        latency_ms: t0.elapsed().as_millis() as u64,
    });

    // 3. chronyc tracking
    let t0 = Instant::now();
    let r3 = run_safe_cmd("chronyc tracking 2>&1", sudo);
    results.push(CheckResultItem {
        name: "Sincronismo de Tempo (Chrony NTP)".to_string(),
        command: "chronyc tracking".to_string(),
        ok: r3.success && r3.stdout.contains("Reference ID"),
        output: if r3.success { "Relógio sincronizado".to_string() } else { r3.stderr },
        latency_ms: t0.elapsed().as_millis() as u64,
    });

    // 4. klist
    let t0 = Instant::now();
    let r4 = run_safe_cmd("klist 2>&1", sudo);
    results.push(CheckResultItem {
        name: "Ticket Kerberos Local (klist)".to_string(),
        command: "klist".to_string(),
        ok: r4.success,
        output: if r4.success { "Tickets Kerberos ativos".to_string() } else { "Nenhum ticket Kerberos em cache".to_string() },
        latency_ms: t0.elapsed().as_millis() as u64,
    });

    // 5. SRV Records (_ldap._tcp, _kerberos._tcp)
    for srv in ["_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_kpasswd._udp"] {
        let t0 = Instant::now();
        let cmd = format!("host -t SRV {}.{} 127.0.0.1 2>&1", srv, realm);
        let rx = run_safe_cmd(&cmd, sudo);
        results.push(CheckResultItem {
            name: format!("Localizador de Serviço ({}.{})", srv, realm),
            command: cmd,
            ok: rx.success && rx.stdout.contains("has SRV record"),
            output: if rx.success { "Registro SRV resolvido com sucesso".to_string() } else { rx.stdout },
            latency_ms: t0.elapsed().as_millis() as u64,
        });
    }

    Json(ApiResponse {
        success: true,
        message: format!("Checklist operacional concluído: {} itens verificados", results.len()),
        data: Some(results),
        dry_run: false,
        correlation_id: None,
    })
}
