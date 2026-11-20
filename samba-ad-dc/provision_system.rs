// ==============================================================================
// Astral AD & Hybrid DNS - Provision System & Host Setup (Rust)
// ==============================================================================

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::Command;

pub fn checked_run(args: &[&str]) -> Result<String, String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("Falha ao executar {:?}: {}", args, e))?;
    if !output.status.success() {
        let err_str = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("Comando {:?} falhou: {}", args, err_str));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn atomic_write<P: AsRef<Path>>(path: P, content: &[u8], _mode: u32) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Falha ao criar diretório {:?}: {}", parent, e))?;
    }
    let tmp_path = path.with_extension("tmp_astral");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| format!("Falha ao abrir {:?}: {}", tmp_path, e))?;
        file.write_all(content).map_err(|e| format!("Falha ao escrever {:?}: {}", tmp_path, e))?;
        file.sync_all().map_err(|e| format!("Falha ao sincronizar {:?}: {}", tmp_path, e))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| format!("Falha ao mover {:?} para {:?}: {}", tmp_path, path, e))?;
    Ok(())
}

pub fn allocate_ca_port(preferred: u16) -> Result<u16, String> {
    let mut used = HashSet::new();
    if let Ok(output) = Command::new("ss").args(["-H", "-lntup"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 4 {
                if let Some(port_str) = fields[4].rsplit(':').next() {
                    if let Ok(p) = port_str.parse::<u16>() {
                        used.insert(p);
                    }
                }
            }
        }
    }

    let candidates = [preferred, 9443, 10443];
    for port in candidates.into_iter().chain(10444..=65535) {
        if used.contains(&port) {
            continue;
        }
        // Test binding TCP and UDP
        let tcp_ok = TcpListener::bind(("0.0.0.0", port)).is_ok();
        let udp_ok = UdpSocket::bind(("0.0.0.0", port)).is_ok();
        if tcp_ok && udp_ok {
            return Ok(port);
        }
    }
    Err("Não foi encontrada porta TCP/UDP livre para a CA Step.".to_string())
}

pub fn firewall_rules(role: &str, step_ca: bool, ca_port: u16) -> (Vec<u16>, Vec<u16>) {
    let mut tcp = vec![53, 88, 135, 139, 389, 445, 464, 636, 8095];
    let mut udp = vec![53, 88, 123, 137, 138, 389, 464];

    if role == "dc1" || role == "replica_dc" || role == "dc" {
        tcp.extend_from_slice(&[3268, 3269]); // Global Catalog
    }
    if step_ca {
        tcp.push(ca_port);
    }
    tcp.sort_unstable();
    tcp.dedup();
    udp.sort_unstable();
    udp.dedup();
    (tcp, udp)
}

pub fn apply_firewall(role: &str, step_ca: bool, ca_port: u16) -> Result<usize, String> {
    let (tcp_ports, udp_ports) = firewall_rules(role, step_ca, ca_port);
    let mut added = 0;

    // Check if firewalld is active
    let firewalld_active = Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if firewalld_active {
        for port in &tcp_ports {
            let arg = format!("{}/tcp", port);
            let _ = Command::new("firewall-cmd").args(["--permanent", "--add-port", &arg]).output();
            added += 1;
        }
        for port in &udp_ports {
            let arg = format!("{}/udp", port);
            let _ = Command::new("firewall-cmd").args(["--permanent", "--add-port", &arg]).output();
            added += 1;
        }
        let _ = Command::new("firewall-cmd").arg("--reload").output();
        return Ok(added);
    }

    // Fallback to iptables
    for port in &tcp_ports {
        let p_str = port.to_string();
        let check = Command::new("iptables")
            .args(["-C", "INPUT", "-p", "tcp", "--dport", &p_str, "-j", "ACCEPT"])
            .output();
        if let Ok(res) = check {
            if !res.status.success() {
                let _ = Command::new("iptables")
                    .args(["-I", "INPUT", "1", "-p", "tcp", "--dport", &p_str, "-j", "ACCEPT"])
                    .output();
                added += 1;
            }
        }
    }
    for port in &udp_ports {
        let p_str = port.to_string();
        let check = Command::new("iptables")
            .args(["-C", "INPUT", "-p", "udp", "--dport", &p_str, "-j", "ACCEPT"])
            .output();
        if let Ok(res) = check {
            if !res.status.success() {
                let _ = Command::new("iptables")
                    .args(["-I", "INPUT", "1", "-p", "udp", "--dport", &p_str, "-j", "ACCEPT"])
                    .output();
                added += 1;
            }
        }
    }
    Ok(added)
}

pub fn configure_hosts(root: &Path, hostname: &str, ip: &str) -> Result<(), String> {
    let hosts_path = root.join("etc/hosts");
    let mut content = fs::read_to_string(&hosts_path).unwrap_or_default();
    let entry = format!("{} {}\n", ip, hostname);

    if !content.contains(hostname) && !content.contains(ip) {
        content.push_str(&entry);
        atomic_write(&hosts_path, content.as_bytes(), 0o644)?;
    }
    let _ = Command::new("hostnamectl").args(["set-hostname", hostname]).output();
    Ok(())
}

pub fn configure_chrony(root: &Path) -> Result<(), String> {
    let chrony_conf_path = if root.join("etc/chrony/chrony.conf").exists() {
        root.join("etc/chrony/chrony.conf")
    } else {
        root.join("etc/chrony.conf")
    };

    if chrony_conf_path.exists() {
        let mut content = fs::read_to_string(&chrony_conf_path).unwrap_or_default();
        let signd_dir = "/var/lib/samba/ntp_signd";
        let directive = format!("\nntpsigndsocket {}\n", signd_dir);
        if !content.contains("ntpsigndsocket") {
            content.push_str(&directive);
            atomic_write(&chrony_conf_path, content.as_bytes(), 0o644)?;
        }
    }

    // Reload AppArmor profile if exists
    let apparmor_chrony = root.join("etc/apparmor.d/usr.sbin.chronyd");
    if apparmor_chrony.exists() {
        let _ = Command::new("apparmor_parser").args(["-r", apparmor_chrony.to_str().unwrap()]).output();
    }

    // Restart chrony
    let _ = Command::new("systemctl").args(["restart", "chronyd"]).output();
    let _ = Command::new("systemctl").args(["restart", "chrony"]).output();
    Ok(())
}

pub fn enable_selinux_samba_dc(root: &Path) {
    if root.join("sys/fs/selinux/enforce").exists() {
        if let Ok(res) = Command::new("getsebool").arg("samba_domain_controller").output() {
            let out = String::from_utf8_lossy(&res.stdout);
            if out.contains("off") {
                let _ = Command::new("setsebool").args(["-P", "samba_domain_controller", "on"]).output();
            }
        }
    }
}
