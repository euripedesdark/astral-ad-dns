use std::process::Command;
use tracing::{info, error};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

pub fn sanitize_arg(s: &str) -> String {
    s.replace('\'', "")
}

/// Run a command safely, using sudo if unprivileged.
/// Strictly forbids any destructive firewall operations (flush/clear chains).
pub fn run_safe_cmd(cmd: &str, sudo_pass: Option<&str>) -> CommandResult {
    // CRITICAL SECURITY CONSTRAINT:
    // Never allow wiping or flushing firewall rules under any circumstance.
    let lower = cmd.to_lowercase();
    if lower.contains("iptables -f") || lower.contains("iptables -x") || lower.contains("nft flush") || lower.contains("firewall-cmd --complete-reload") {
        error!("Destructive firewall command rejected: {}", cmd);
        return CommandResult {
            success: false,
            stdout: String::new(),
            stderr: "Operation rejected: Destructive firewall flushing is strictly prohibited to protect running infrastructure.".to_string(),
            code: 403,
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
            }
        }
        Err(e) => {
            error!("Command execution failed: {}", e);
            CommandResult {
                success: false,
                stdout: String::new(),
                stderr: e.to_string(),
                code: -1,
            }
        }
    }
}

/// Safely ensures a port is open in iptables without flushing any existing rules.
/// Checks with -C first, and appends with -A only if absent.
pub fn ensure_firewall_port_open(port: u16, proto: &str, sudo_pass: Option<&str>) -> bool {
    let check_cmd = format!("iptables -C INPUT -p {} -m {} --dport {} -j ACCEPT 2>/dev/null", proto, proto, port);
    let check_res = run_safe_cmd(&check_cmd, sudo_pass);
    if check_res.success {
        info!("Firewall port {}/{} is already open.", port, proto);
        return true;
    }

    info!("Safely appending firewall rule for port {}/{}...", port, proto);
    let add_cmd = format!(
        "iptables -A INPUT -p {} -m {} --dport {} -j ACCEPT && (iptables-save > /etc/sysconfig/iptables 2>/dev/null || true)",
        proto, proto, port
    );
    let add_res = run_safe_cmd(&add_cmd, sudo_pass);
    add_res.success
}

pub fn check_service_active(service: &str, sudo_pass: Option<&str>) -> bool {
    let res = run_safe_cmd(&format!("systemctl is-active {}", service), sudo_pass);
    res.stdout.trim() == "active"
}
