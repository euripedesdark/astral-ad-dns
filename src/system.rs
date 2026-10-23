use std::process::Command;
use tracing::{info, error};
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

/// Verifica se o comando contém instruções destrutivas de firewall (case-sensitive para flags curtas, sem falsos positivos em -p tcp ou --dport).
pub fn is_destructive_firewall(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    if lower.contains("nft flush") || lower.contains("firewall-cmd --complete-reload") {
        return true;
    }
    // Flags curtas de iptables são sensíveis a maiúsculas: -P (Policy) vs -p (protocolo); -D (delete) vs -d (destination)
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
/// Proíbe terminantemente descarregar regras de firewall.
pub fn run_safe_cmd(cmd: &str, sudo_pass: Option<&str>) -> CommandResult {
    run_cmd_dry(cmd, sudo_pass, false)
}

pub fn run_cmd_dry(cmd: &str, sudo_pass: Option<&str>, dry_run: bool) -> CommandResult {
    let display_cmd = mask_passwords(cmd);

    // RESTRIÇÃO CRÍTICA DE SEGURANÇA:
    // Nunca permitir limpar regras de firewall ativas sob nenhuma circunstância.
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
        Err(e) => {
            error!("Falha na execução do comando: {}", e);
            CommandResult {
                success: false,
                stdout: String::new(),
                stderr: e.to_string(),
                code: -1,
                dry_run: false,
                command: display_cmd,
            }
        }
    }
}

/// Portas oficiais recomendadas para o Samba 4 Active Directory Domain Controller
pub fn samba_ad_ports() -> Vec<PortRule> {
    let r = |p: &str, port: &str, l: &str| PortRule { proto: p.into(), port: port.into(), label: l.into() };
    vec![
        r("tcp", "53", "DNS (TCP)"),
        r("udp", "53", "DNS (UDP)"),
        r("tcp", "88", "Kerberos KDC (TCP)"),
        r("udp", "88", "Kerberos KDC (UDP)"),
        r("tcp", "135", "RPC Endpoint Mapper"),
        r("udp", "137", "NetBIOS Name Service"),
        r("udp", "138", "NetBIOS Datagram"),
        r("tcp", "139", "NetBIOS Session"),
        r("tcp", "389", "LDAP (TCP)"),
        r("udp", "389", "CLDAP (UDP)"),
        r("tcp", "445", "SMB Direct over IP"),
        r("tcp", "464", "Kerberos Change Password (TCP)"),
        r("udp", "464", "Kerberos Change Password (UDP)"),
        r("tcp", "636", "LDAPS (SSL)"),
        r("tcp", "3268", "Global Catalog"),
        r("tcp", "3269", "Global Catalog SSL"),
        r("tcp", "49152:65535", "RPC Dinâmico (High Ports)"),
        r("udp", "123", "NTP Time Sync (Chrony)"),
        r("tcp", "8095", "Console Web Astral AD-DNS"),
    ]
}

/// Verifica se a porta está aberta na chain INPUT do iptables
pub fn check_port_open(proto: &str, port: &str, sudo_pass: Option<&str>) -> bool {
    let check_cmd = format!("iptables -C INPUT -p {} -m {} --dport {} -j ACCEPT 2>/dev/null", proto, proto, port);
    let check_res = run_safe_cmd(&check_cmd, sudo_pass);
    check_res.success
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
        "iptables -I INPUT 1 -p {} -m {} --dport {} -m comment --comment \"astral-ad:{}\" -j ACCEPT && (iptables-save > /etc/sysconfig/iptables 2>/dev/null || true)",
        rule.proto, rule.proto, rule.port, rule.label
    );

    run_cmd_dry(&add_cmd, sudo_pass, dry_run)
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
        // Comandos válidos NÃO podem ser falsos positivos
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

        let cmd2 = "samba-tool user create joao SenhaForte123! --mail=joao@srv.cloud";
        assert!(mask_passwords(cmd2).contains("joao"));

        let cmd3 = "samba-tool dns add 127.0.0.1 srv.cloud ad A 192.168.2.10 -U administrator --password='Copa@@2026'";
        let masked3 = mask_passwords(cmd3);
        assert!(!masked3.contains("Copa@@2026"));
        assert!(masked3.contains("--password='********'"));
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
