pub mod firewall_migration;

use std::process::Command;
use tracing::{info, error, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub dry_run: bool,
    pub command: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PortRule {
    pub proto: String,
    pub port: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledServices {
    pub samba_ad: bool,
    pub bind: bool,
    pub chrony: bool,
    pub web_console: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortReconcileItem {
    pub proto: String,
    pub port: String,
    pub label: String,
    pub status: String, // "OPEN", "CORRECTED", "FAILED"
    pub is_listening: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallReconcileReport {
    pub services: EnabledServices,
    pub total_ports: usize,
    pub open_count: usize,
    pub corrected_count: usize,
    pub failed_count: usize,
    pub ports: Vec<PortReconcileItem>,
}

pub fn sanitize_arg(s: &str) -> String {
    s.replace('\'', "").replace('"', "").replace(';', "").replace('&', "").replace('|', "")
}

/// Mascara credenciais e senhas nos comandos para proteger logs e auditoria.
pub fn mask_passwords(cmd: &str) -> String {
    let mut masked = cmd.to_string();
    let patterns = [
        "--adminpass=",
        "--newpassword=",
        "--password=",
        "-W ",
    ];

    for pat in patterns {
        if let Some(pos) = masked.find(pat) {
            let mut start = pos + pat.len();
            let mut has_quote = false;
            let mut quote_char = ' ';
            if start < masked.len() {
                let first = masked[start..].chars().next().unwrap();
                if first == '\'' || first == '"' {
                    has_quote = true;
                    quote_char = first;
                    start += 1;
                }
            }
            let remainder = &masked[start..];
            let end = if has_quote {
                remainder.find(quote_char).map(|p| start + p).unwrap_or(masked.len())
            } else {
                remainder.find(|c: char| c.is_whitespace()).map(|p| start + p).unwrap_or(masked.len())
            };
            masked.replace_range(start..end, "********");
        }
    }
    masked
}

/// Verifica se o comando contém instruções destrutivas de firewall.
pub fn is_destructive_firewall(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    if lower.contains("nft flush") || lower.contains("firewall-cmd --complete-reload") {
        return true;
    }
    for part in cmd.split_whitespace() {
        match part {
            "-F" | "-X" | "-Z" | "-P" | "-D" | "-R" => return true,
            _ => {}
        }
    }
    for part in lower.split_whitespace() {
        match part {
            "--flush" | "--delete-chain" | "--zero" | "--policy" | "--delete" | "--replace" => return true,
            _ => {}
        }
    }
    false
}

/// Executa um comando no sistema com opção de simulação (dry-run).
pub fn run_safe_cmd(cmd: &str, sudo_pass: Option<&str>) -> CommandResult {
    run_cmd_dry(cmd, sudo_pass, false)
}

pub fn run_cmd_dry(cmd: &str, sudo_pass: Option<&str>, dry_run: bool) -> CommandResult {
    let display_cmd = mask_passwords(cmd);

    if is_destructive_firewall(cmd) {
        error!("Comando destrutivo de firewall rejeitado: {}", display_cmd);
        return CommandResult {
            success: false,
            stdout: String::new(),
            stderr: "Operação recusada: É estritamente proibido descarregar ou alterar políticas de firewall para proteger a infraestrutura ativa.".to_string(),
            code: 403,
            dry_run,
            command: display_cmd,
        };
    }

    if dry_run {
        info!("[SIMULAÇÃO/DRY-RUN] Execução prevista: {}", display_cmd);
        return CommandResult {
            success: true,
            stdout: format!("[SIMULAÇÃO] O seguinte comando seria executado:\n{}", display_cmd),
            stderr: String::new(),
            code: 0,
            dry_run: true,
            command: display_cmd,
        };
    }

    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);

    let full_cmd = if is_root {
        cmd.to_string()
    } else if let Some(pass) = sudo_pass {
        let safe_pass = pass.replace('\'', "");
        format!("echo '{}' | sudo -S sh -c \"{}\"", safe_pass, cmd.replace('"', "\\\""))
    } else {
        cmd.to_string()
    };

    let output = Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let code = out.status.code().unwrap_or(-1);

            CommandResult {
                success: out.status.success(),
                stdout,
                stderr,
                code,
                dry_run: false,
                command: display_cmd,
            }
        }
        Err(e) => CommandResult {
            success: false,
            stdout: String::new(),
            stderr: format!("Erro ao disparar comando: {}", e),
            code: -1,
            dry_run: false,
            command: display_cmd,
        },
    }
}

/// Verifica se o Samba Active Directory está configurado na máquina
pub fn is_ad_configured() -> bool {
    if let Ok(content) = std::fs::read_to_string("/etc/samba/smb.conf") {
        let l = content.to_lowercase();
        if l.contains("server role") && l.contains("active directory domain controller") {
            return true;
        }
    }
    let res = Command::new("systemctl").args(["is-active", "samba"]).output();
    if let Ok(out) = res {
        if String::from_utf8_lossy(&out.stdout).trim() == "active" {
            return true;
        }
    }
    let res_dc = Command::new("systemctl").args(["is-active", "samba-ad-dc"]).output();
    if let Ok(out) = res_dc {
        if String::from_utf8_lossy(&out.stdout).trim() == "active" {
            return true;
        }
    }
    false
}

/// Detecta os serviços habilitados e configurados no host
pub fn detect_enabled_services(sudo_pass: Option<&str>) -> EnabledServices {
    let samba_ad = is_ad_configured();
    let bind = check_service_active("named", sudo_pass)
        || check_service_active("named-chroot", sudo_pass)
        || check_service_active("bind9", sudo_pass)
        || std::path::Path::new("/etc/named.conf").exists();
    let chrony = check_service_active("chronyd", sudo_pass)
        || check_service_active("ntpd", sudo_pass)
        || std::path::Path::new("/etc/chrony.conf").exists();
    let web_console = true;

    EnabledServices {
        samba_ad,
        bind,
        chrony,
        web_console,
    }
}

/// Retorna exclusivamente as portas necessárias para os serviços efetivamente habilitados
pub fn required_ports_for_services(services: &EnabledServices) -> Vec<PortRule> {
    let r = |p: &str, port: &str, l: &str| PortRule { proto: p.into(), port: port.into(), label: l.into() };
    let mut ports = Vec::new();

    // Portas do Samba AD somente se habilitado/configurado
    if services.samba_ad {
        ports.push(r("tcp", "88", "Kerberos KDC (TCP)"));
        ports.push(r("udp", "88", "Kerberos KDC (UDP)"));
        ports.push(r("tcp", "135", "RPC Endpoint Mapper"));
        ports.push(r("udp", "137", "NetBIOS Name Service"));
        ports.push(r("udp", "138", "NetBIOS Datagram"));
        ports.push(r("tcp", "139", "NetBIOS Session"));
        ports.push(r("tcp", "389", "LDAP (TCP)"));
        ports.push(r("udp", "389", "CLDAP (UDP)"));
        ports.push(r("tcp", "445", "SMB Direct over IP"));
        ports.push(r("tcp", "464", "Kerberos Change Password (TCP)"));
        ports.push(r("udp", "464", "Kerberos Change Password (UDP)"));
        ports.push(r("tcp", "636", "LDAPS (SSL)"));
        ports.push(r("tcp", "3268", "Global Catalog"));
        ports.push(r("tcp", "3269", "Global Catalog SSL"));
        ports.push(r("tcp", "49152:65535", "RPC Dinâmico TCP (High Ports)"));
        ports.push(r("udp", "49152:65535", "RPC Dinâmico UDP (High Ports)"));
        ports.push(r("tcp", "8443", "Smallstep Step-CA PKI (TCP)"));
    }

    // Portas de DNS (se Samba AD ou BIND 9 estiverem ativos)
    if services.samba_ad || services.bind {
        ports.push(r("tcp", "53", "DNS Server (TCP)"));
        ports.push(r("udp", "53", "DNS Server (UDP)"));
        ports.push(r("tcp", "5353", "BIND Hybrid Recursivo (TCP)"));
        ports.push(r("udp", "5353", "BIND Hybrid Recursivo (UDP)"));
    }
    if services.bind {
        ports.push(r("tcp", "953", "BIND RNDC Control"));
    }

    // NTP Time Sync (Chrony)
    if services.chrony {
        ports.push(r("udp", "123", "NTP Time Sync (Chrony)"));
    }

    // Console Web Administrativo Astral AD & DNS
    if services.web_console {
        ports.push(r("tcp", "8095", "Console Web Astral AD-DNS"));
    }

    ports
}

/// Portas oficiais recomendadas para o Samba 4 Active Directory Domain Controller
pub fn samba_ad_ports() -> Vec<PortRule> {
    let services = EnabledServices {
        samba_ad: true,
        bind: true,
        chrony: true,
        web_console: true,
    };
    required_ports_for_services(&services)
}

/// Verifica se a porta está aberta na chain INPUT do iptables
pub fn check_port_open(proto: &str, port: &str, sudo_pass: Option<&str>) -> bool {
    let check_cmd = format!("iptables -C INPUT -p {} -m {} --dport {} -j ACCEPT 2>/dev/null", proto, proto, port);
    let check_res = run_safe_cmd(&check_cmd, sudo_pass);
    if check_res.success {
        return true;
    }
    // Fallback com iptables -S para regras que possuam comentários ou flags adicionais
    let check_s = format!("iptables -S INPUT | grep -E -- \"-p {} .*--dport {} .*-j ACCEPT\"", proto, port);
    let s_res = run_safe_cmd(&check_s, sudo_pass);
    s_res.success
}

/// Abre porta no firewall de forma idempotente e segura, usando -I INPUT 1
pub fn open_port_safe(rule: &PortRule, sudo_pass: Option<&str>, dry_run: bool) -> CommandResult {
    let port_valid = !rule.port.is_empty()
        && rule.port.split(':').all(|p| p.parse::<u16>().is_ok())
        && rule.port.split(':').count() <= 2;
    let proto_valid = rule.proto == "tcp" || rule.proto == "udp";

    if !port_valid || !proto_valid {
        return CommandResult {
            success: false,
            stdout: String::new(),
            stderr: format!("Regra de porta inválida: {}/{}", rule.port, rule.proto),
            code: 400,
            dry_run,
            command: format!("{}/{}", rule.proto, rule.port),
        };
    }

    if check_port_open(&rule.proto, &rule.port, sudo_pass) {
        return CommandResult {
            success: true,
            stdout: format!("A porta {}/{} já se encontra aberta e ativa.", rule.port, rule.proto),
            stderr: String::new(),
            code: 0,
            dry_run,
            command: format!("iptables -C INPUT -p {} --dport {}", rule.proto, rule.port),
        };
    }

    let add_cmd = format!(
        "iptables -I INPUT 1 -p {} -m {} --dport {} -j ACCEPT && (iptables-save > /etc/sysconfig/iptables 2>/dev/null || true)",
        rule.proto, rule.proto, rule.port
    );

    run_cmd_dry(&add_cmd, sudo_pass, dry_run)
}

/// Reconcilia e abre automaticamente as portas necessárias para os serviços ativos
pub fn auto_reconcile_firewall_ports(
    sudo_pass: Option<&str>,
    dry_run: bool,
) -> FirewallReconcileReport {
    let services = detect_enabled_services(sudo_pass);
    let rules = required_ports_for_services(&services);
    let mut items = Vec::new();

    let mut open_cnt = 0;
    let mut corrected_cnt = 0;
    let mut failed_cnt = 0;

    let ss_out = run_safe_cmd("ss -tuln 2>/dev/null", sudo_pass).stdout;

    for r in &rules {
        let is_open_initially = check_port_open(&r.proto, &r.port, sudo_pass);
        let clean_port = r.port.split(':').next().unwrap_or(&r.port);
        let is_listening = ss_out.contains(&format!(":{}", clean_port));

        if is_open_initially {
            open_cnt += 1;
            items.push(PortReconcileItem {
                proto: r.proto.clone(),
                port: r.port.clone(),
                label: r.label.clone(),
                status: "OPEN".to_string(),
                is_listening,
            });
        } else if dry_run {
            corrected_cnt += 1;
            items.push(PortReconcileItem {
                proto: r.proto.clone(),
                port: r.port.clone(),
                label: r.label.clone(),
                status: "CORRECTED".to_string(),
                is_listening,
            });
        } else {
            let open_res = open_port_safe(r, sudo_pass, false);
            if open_res.success && check_port_open(&r.proto, &r.port, sudo_pass) {
                corrected_cnt += 1;
                items.push(PortReconcileItem {
                    proto: r.proto.clone(),
                    port: r.port.clone(),
                    label: r.label.clone(),
                    status: "CORRECTED".to_string(),
                    is_listening,
                });
                info!("Porta {}/{} corrigida e aberta automaticamente no firewall (iptables).", r.port, r.proto);
            } else {
                failed_cnt += 1;
                items.push(PortReconcileItem {
                    proto: r.proto.clone(),
                    port: r.port.clone(),
                    label: r.label.clone(),
                    status: "FAILED".to_string(),
                    is_listening,
                });
                warn!("Falha ao abrir automaticamente porta {}/{} no iptables: {}", r.port, r.proto, open_res.stderr);
            }
        }
    }

    FirewallReconcileReport {
        services,
        total_ports: rules.len(),
        open_count: open_cnt,
        corrected_count: corrected_cnt,
        failed_count: failed_cnt,
        ports: items,
    }
}

pub fn ensure_firewall_port_open(port: u16, proto: &str, sudo_pass: Option<&str>) -> bool {
    let rule = PortRule {
        proto: proto.to_string(),
        port: port.to_string(),
        label: "astral-service".to_string(),
    };
    open_port_safe(&rule, sudo_pass, false).success
}

pub fn check_service_active(service: &str, sudo_pass: Option<&str>) -> bool {
    let res = run_safe_cmd(&format!("systemctl is-active {}", service), sudo_pass);
    res.stdout.trim() == "active"
}

/// Desativa o systemd-resolved (libera porta 53) e protege /etc/resolv.conf com chattr +i.
/// Configura estritamente os servidores DNS do AD (local 127.0.0.1 e/ou DC parceiro),
/// sem incluir servidores externos públicos (ex: Google 8.8.8.8) no resolv.conf,
/// uma vez que o BIND 9 / Samba já encaminha consultas públicas via forwarders configurados.
pub fn disable_systemd_resolved_and_protect_dns(realm: &str, sudo_pass: Option<&str>) -> CommandResult {
    configure_ad_dns_resolver(realm, None, sudo_pass)
}

pub fn configure_ad_dns_resolver(realm: &str, partner_dc_ip: Option<&str>, sudo_pass: Option<&str>) -> CommandResult {
    let _ = run_cmd_dry("systemctl stop systemd-resolved 2>/dev/null || true", sudo_pass, false);
    let _ = run_cmd_dry("systemctl disable systemd-resolved 2>/dev/null || true", sudo_pass, false);
    let _ = run_cmd_dry("chattr -i /etc/resolv.conf 2>/dev/null || true", sudo_pass, false);
    let _ = run_cmd_dry("rm -f /etc/resolv.conf", sudo_pass, false);

    let search_domain = realm.trim().to_lowercase();
    let mut conf = format!("search {}\\n", search_domain);
    if let Some(partner_ip) = partner_dc_ip {
        let p = partner_ip.trim();
        if !p.is_empty() && p != "127.0.0.1" {
            conf.push_str(&format!("nameserver {}\\n", p));
        }
    }
    conf.push_str("nameserver 127.0.0.1\\n");

    let write_cmd = format!("sh -c 'printf \"{}\" > /etc/resolv.conf && chattr +i /etc/resolv.conf'", conf);
    run_cmd_dry(&write_cmd, sudo_pass, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_destructive_firewall() {
        assert!(is_destructive_firewall("iptables -F"));
        assert!(is_destructive_firewall("iptables --flush"));
        assert!(is_destructive_firewall("iptables -X"));
        assert!(is_destructive_firewall("iptables -Z"));
        assert!(is_destructive_firewall("iptables -P INPUT DROP"));
        assert!(is_destructive_firewall("nft flush ruleset"));
        assert!(is_destructive_firewall("firewall-cmd --complete-reload"));
        assert!(!is_destructive_firewall("iptables -C INPUT -p tcp --dport 53 -j ACCEPT"));
        assert!(!is_destructive_firewall("iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT"));
        assert!(!is_destructive_firewall("samba-tool user list"));
    }

    #[test]
    fn test_mask_passwords() {
        let cmd = "samba-tool domain provision --realm=SRVCLOUD.CLOUD --adminpass=Secret123 --dns-backend=BIND9_DLZ";
        let masked = mask_passwords(cmd);
        assert!(!masked.contains("Secret123"));
        assert!(masked.contains("--adminpass=********"));
    }

    #[test]
    fn test_dry_run_does_not_execute() {
        let res = run_cmd_dry("reboot", None, true);
        assert!(res.success);
        assert!(res.dry_run);
        assert!(res.stdout.contains("[SIMULAÇÃO]"));
    }

    #[test]
    fn test_samba_ad_ports_count() {
        let ports = samba_ad_ports();
        assert!(ports.len() >= 18);
        assert!(ports.iter().any(|p| p.port == "389" && p.proto == "tcp"));
        assert!(ports.iter().any(|p| p.port == "88" && p.proto == "tcp"));
        assert!(ports.iter().any(|p| p.port == "53" && p.proto == "udp"));
    }
}
