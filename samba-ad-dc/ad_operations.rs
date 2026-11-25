// ==============================================================================
// Astral AD & Hybrid DNS - Active Directory Operations CLI Engine (Rust)
// ==============================================================================

pub mod directory_config;
pub mod provision_system;
pub mod provision_tls;
pub mod provision_pki;
pub mod provision_ad_step_ca;
pub mod provision_dc1;
pub mod provision_workflow;
pub mod ad_forensics;
pub mod dc_lifecycle;
pub mod pki_management;
pub mod host_prep;

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use serde_json::Value;

use directory_config::{detect_distro_profile, DistroProfile};
use provision_system::atomic_write;

pub fn generate_distro_bind_config(
    family: &str,
    forwarders: &[String],
    directory: &str,
    port: u16,
    root: &Path,
) -> String {
    let fwd_entries: Vec<String> = forwarders.iter().map(|ip| format!("        {};\n", ip)).collect();
    let fwd_block = fwd_entries.concat();

    let standard_opts = format!(
        "options {{\n    directory \"{}\";\n    listen-on port {} {{ 127.0.0.1; }};\n    listen-on-v6 {{ none; }};\n    allow-query {{ localhost; }};\n    allow-recursion {{ localhost; }};\n    allow-query-cache {{ localhost; }};\n    recursion yes;\n    forward only;\n    forwarders {{\n{}}};\n    dnssec-validation auto;\n    max-cache-size 64m;\n    minimal-responses yes;\n}};\n",
        directory, port, fwd_block
    );

    match family {
        "debian" => {
            let main_conf = root.join("etc/bind/named.conf");
            if !main_conf.exists() || fs::read_to_string(&main_conf).unwrap_or_default().trim().is_empty() {
                let mut lines = vec![
                    "// Astral AD & Hybrid DNS - BIND 9 Main Configuration (Debian)".to_string(),
                    "include \"/etc/bind/named.conf.options\";".to_string(),
                    "include \"/etc/bind/named.conf.local\";".to_string(),
                ];
                if root.join("etc/bind/named.conf.default-zones").exists() {
                    lines.push("include \"/etc/bind/named.conf.default-zones\";".to_string());
                }
                let _ = atomic_write(&main_conf, lines.join("\n").as_bytes(), 0o644);
            }
            let local_conf = root.join("etc/bind/named.conf.local");
            if !local_conf.exists() {
                let _ = atomic_write(&local_conf, b"// Astral AD & Hybrid DNS - Local configuration\n", 0o644);
            }
            standard_opts
        }
        "redhat" => {
            let crypto_inc = if root.join("etc/crypto-policies/back-ends/bind.config").exists() {
                "    include \"/etc/crypto-policies/back-ends/bind.config\";\n"
            } else {
                ""
            };
            let hint_file = if root.join("etc/named.ca").exists() {
                "/etc/named.ca"
            } else {
                "named.ca"
            };
            let redhat_opts = format!(
                "options {{\n    directory \"{}\";\n    dump-file \"/var/named/data/cache_dump.db\";\n    statistics-file \"/var/named/data/named_stats.txt\";\n    memstatistics-file \"/var/named/data/named_mem_stats.txt\";\n    secroots-file \"/var/named/data/named.secroots\";\n    recursing-file \"/var/named/data/named.recursing\";\n\n    listen-on port {} {{ 127.0.0.1; }};\n    listen-on-v6 {{ none; }};\n\n    allow-query {{ localhost; }};\n    allow-recursion {{ localhost; }};\n    allow-query-cache {{ localhost; }};\n\n    recursion yes;\n    forward only;\n    forwarders {{\n{}}};\n\n    dnssec-validation auto;\n    max-cache-size 64m;\n    minimal-responses yes;\n    managed-keys-directory \"/var/named/dynamic\";\n    pid-file \"/run/named/named.pid\";\n    session-keyfile \"/run/named/session.key\";\n{}}};\n",
                directory, port, fwd_block, crypto_inc
            );
            let mut content = vec![
                "// Astral AD & Hybrid DNS - BIND 9 Configuration (Fedora / RHEL)".to_string(),
                redhat_opts.trim().to_string(),
                "".to_string(),
                "logging {\n    channel default_debug {\n        file \"data/named.run\";\n        severity dynamic;\n    };\n};".to_string(),
                "".to_string(),
                format!("zone \".\" IN {{\n    type hint;\n    file \"{}\";\n}};", hint_file),
            ];
            if root.join("etc/named.rfc1912.zones").exists() {
                content.push("include \"/etc/named.rfc1912.zones\";".to_string());
            }
            if root.join("etc/named.root.key").exists() {
                content.push("include \"/etc/named.root.key\";".to_string());
            }
            content.join("\n") + "\n"
        }
        "arch" => {
            let arch_opts = format!(
                "options {{\n    directory \"{}\";\n    pid-file \"/run/named/named.pid\";\n    listen-on port {} {{ 127.0.0.1; }};\n    listen-on-v6 {{ none; }};\n    allow-query {{ localhost; }};\n    allow-recursion {{ localhost; }};\n    allow-query-cache {{ localhost; }};\n    recursion yes;\n    forward only;\n    forwarders {{\n{}}};\n    dnssec-validation auto;\n    max-cache-size 64m;\n    minimal-responses yes;\n}};\n",
                directory, port, fwd_block
            );
            let mut content = vec![
                "// Astral AD & Hybrid DNS - BIND 9 Configuration (Arch Linux)".to_string(),
                arch_opts.trim().to_string(),
            ];
            if root.join("var/named/root.hint").exists() {
                content.push("\nzone \".\" IN {\n    type hint;\n    file \"root.hint\";\n};".to_string());
            }
            if root.join("var/named/localhost.zone").exists() {
                content.push("\nzone \"localhost\" IN {\n    type master;\n    file \"localhost.zone\";\n};".to_string());
            }
            if root.join("var/named/127.0.0.zone").exists() {
                content.push("\nzone \"0.0.127.in-addr.arpa\" IN {\n    type master;\n    file \"127.0.0.zone\";\n};".to_string());
            }
            content.join("\n") + "\n"
        }
        "suse" => {
            let suse_opts = format!(
                "options {{\n    directory \"{}\";\n    dump-file \"/var/log/named_dump.db\";\n    statistics-file \"/var/log/named.stats\";\n    listen-on port {} {{ 127.0.0.1; }};\n    listen-on-v6 {{ none; }};\n    allow-query {{ localhost; }};\n    allow-recursion {{ localhost; }};\n    allow-query-cache {{ localhost; }};\n    recursion yes;\n    forward only;\n    forwarders {{\n{}}};\n    dnssec-validation auto;\n    max-cache-size 64m;\n    minimal-responses yes;\n}};\n",
                directory, port, fwd_block
            );
            let mut content = vec![
                "// Astral AD & Hybrid DNS - BIND 9 Configuration (openSUSE / SUSE)".to_string(),
                suse_opts.trim().to_string(),
            ];
            if root.join("var/lib/named/root.hint").exists() {
                content.push("\nzone \".\" in {\n    type hint;\n    file \"root.hint\";\n};".to_string());
            }
            content.join("\n") + "\n"
        }
        _ => standard_opts,
    }
}

pub fn configure_distro_bind_environment(
    root: &Path,
    profile: &DistroProfile,
    _port: u16,
) -> Result<(), String> {
    match profile.family.as_str() {
        "debian" => {
            for def in ["etc/default/named", "etc/default/bind9"] {
                let p = root.join(def);
                if !p.is_symlink() {
                    let text = fs::read_to_string(&p).unwrap_or_default();
                    let lines: Vec<&str> = text
                        .lines()
                        .filter(|l| !l.trim().starts_with("RESOLVCONF=") && !l.trim().starts_with("OPTIONS="))
                        .collect();
                    let new_text = format!("{}\n# Astral AD DNS\nRESOLVCONF=no\nOPTIONS=\"-4 -u bind\"\n", lines.join("\n"));
                    let _ = atomic_write(&p, new_text.trim_start().as_bytes(), 0o644);
                }
            }
            let cache_dir = root.join(profile.bind_work_dir.trim_start_matches('/'));
            let _ = fs::create_dir_all(&cache_dir);
            let _ = Command::new("chown").args(["-R", &format!("{}:{}", profile.bind_user, profile.bind_group), cache_dir.to_str().unwrap()]).output();
        }
        "redhat" => {
            let sysconfig = root.join("etc/sysconfig/named");
            if !sysconfig.is_symlink() {
                let text = fs::read_to_string(&sysconfig).unwrap_or_default();
                if !text.contains("OPTIONS=") {
                    let new_text = format!("{}\n# Astral AD DNS\nOPTIONS=\"-4\"\n", text.trim_end());
                    let _ = atomic_write(&sysconfig, new_text.trim_start().as_bytes(), 0o644);
                }
            }
            for sub in ["data", "dynamic"] {
                let d = root.join(format!("var/named/{}", sub));
                let _ = fs::create_dir_all(&d);
                let _ = Command::new("chown").args([&format!("{}:{}", profile.bind_user, profile.bind_group), d.to_str().unwrap()]).output();
                let _ = Command::new("chmod").args(["770", d.to_str().unwrap()]).output();
            }
        }
        "arch" => {
            let conf_d = root.join("etc/conf.d/named");
            if !conf_d.is_symlink() {
                let text = fs::read_to_string(&conf_d).unwrap_or_default();
                if !text.contains("NAMED_ARGS=") {
                    let new_text = format!("{}\n# Astral AD DNS\nNAMED_ARGS=\"-4 -u named\"\n", text.trim_end());
                    let _ = atomic_write(&conf_d, new_text.trim_start().as_bytes(), 0o644);
                }
            }
            let run_named = root.join("run/named");
            let _ = fs::create_dir_all(&run_named);
            let _ = Command::new("chown").args([&format!("{}:{}", profile.bind_user, profile.bind_group), run_named.to_str().unwrap()]).output();
        }
        "suse" => {
            let sysconfig = root.join("etc/sysconfig/named");
            if !sysconfig.is_symlink() {
                let text = fs::read_to_string(&sysconfig).unwrap_or_default();
                if !text.contains("NAMED_ARGS=") {
                    let new_text = format!("{}\n# Astral AD DNS\nNAMED_ARGS=\"-4\"\n", text.trim_end());
                    let _ = atomic_write(&sysconfig, new_text.trim_start().as_bytes(), 0o644);
                }
            }
            let override_dir = root.join("etc/systemd/system/named.service.d");
            let _ = fs::create_dir_all(&override_dir);
            let dropin = "[Service]\nReadWritePaths=/var/lib/named /run/named /var/log/named /var/lib/samba/bind-dns\n";
            let _ = atomic_write(&override_dir.join("override.conf"), dropin.as_bytes(), 0o644);
            let _ = Command::new("systemctl").arg("daemon-reload").output();
        }
        _ => {}
    }
    Ok(())
}

pub fn configure_bind(request: &Value, root: &Path) -> Result<Vec<String>, String> {
    let mut steps = Vec::new();
    let profile = detect_distro_profile(root);

    // Parse forwarders from request
    let mut forwarders = Vec::new();
    if let Some(fwds) = request.get("forwarders").and_then(|v| v.as_array()) {
        for f in fwds {
            if let Some(s) = f.as_str() {
                let s = s.trim();
                if !s.is_empty() && !forwarders.contains(&s.to_string()) {
                    forwarders.push(s.to_string());
                }
            }
        }
    }
    if forwarders.is_empty() {
        forwarders.push("8.8.8.8".to_string());
        forwarders.push("1.1.1.1".to_string());
    }

    let port: u16 = request.get("port")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)
        .unwrap_or(5353);

    // 1. Prepare directory permissions and distro environment
    if root == Path::new("/") {
        let _ = Command::new("systemctl").args(["mask", "--now", "avahi-daemon.service", "avahi-daemon.socket"]).output();
        let _ = Command::new("systemctl").args(["stop", "avahi-daemon.service", "avahi-daemon.socket"]).output();
    }
    let bind_dir = root.join(profile.bind_work_dir.trim_start_matches('/'));
    fs::create_dir_all(&bind_dir).map_err(|e| e.to_string())?;
    let _ = Command::new("chown").args(["-R", &format!("{}:{}", profile.bind_user, profile.bind_group), bind_dir.to_str().unwrap()]).output();

    configure_distro_bind_environment(root, &profile, port)?;

    // 2. Generate and write configuration file
    let config_path = root.join(profile.bind_options_file.trim_start_matches('/'));
    if let Some(parent) = config_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let config_content = generate_distro_bind_config(&profile.family, &forwarders, &profile.bind_work_dir, port, root);
    atomic_write(&config_path, config_content.as_bytes(), 0o640)?;
    let _ = Command::new("chown").args([&format!("root:{}", profile.bind_group), config_path.to_str().unwrap()]).output();
    steps.push(format!("Configuração BIND gerada para {}: {:?}", profile.family, config_path));

    // Check with named-checkconf
    let check_res = Command::new("named-checkconf").arg(&config_path).output();
    if let Ok(res) = check_res {
        if !res.status.success() {
            let err = String::from_utf8_lossy(&res.stderr);
            return Err(format!("named-checkconf falhou em {:?}: {}", config_path, err));
        }
    }

    // 3. SELinux rules if enabled
    let selinux_enforce = root.join("sys/fs/selinux/enforce");
    if selinux_enforce.exists() {
        let _ = Command::new("semanage").args(["port", "-a", "-t", "dns_port_t", "-p", "udp", &port.to_string()]).output();
        let _ = Command::new("semanage").args(["port", "-a", "-t", "dns_port_t", "-p", "tcp", &port.to_string()]).output();
        steps.push(format!("SELinux: porta {} rotulada como dns_port_t.", port));
    }

    // 4. AppArmor configuration if enabled
    let apparmor_named = root.join("etc/apparmor.d/local/usr.sbin.named");
    if apparmor_named.parent().map(|p| p.exists()).unwrap_or(false) {
        let rule = "/var/lib/samba/private/dns.keytab r,\n/var/lib/samba/private/named.conf r,\n/var/lib/samba/bind-dns/** rwk,\n";
        let _ = atomic_write(&apparmor_named, rule.as_bytes(), 0o644);
        let _ = Command::new("apparmor_parser").args(["-r", "/etc/apparmor.d/usr.sbin.named"]).output();
        steps.push("AppArmor: permissões locais do BIND atualizadas.".to_string());
    }

    // 5. Restart and enable BIND service
    let s_res = Command::new("systemctl").args(["restart", &profile.bind_service]).output();
    if let Ok(res) = s_res {
        if res.status.success() {
            let _ = Command::new("systemctl").args(["enable", &profile.bind_service]).output();
            steps.push(format!("Serviço de DNS ({}) ativo e configurado.", profile.bind_service));
        } else {
            let err = String::from_utf8_lossy(&res.stderr);
            return Err(format!("Falha ao iniciar serviço BIND ({}): {}", profile.bind_service, err));
        }
    }

    Ok(steps)
}

fn print_json_and_exit(success: bool, data_key: &str, data: Value, code: i32) {
    let mut map = serde_json::Map::new();
    map.insert("success".to_string(), Value::Bool(success));
    map.insert(data_key.to_string(), data);
    println!("{}", serde_json::to_string(&Value::Object(map)).unwrap());
    std::process::exit(code);
}

fn print_error_and_exit(err_msg: &str) {
    let mut map = serde_json::Map::new();
    map.insert("success".to_string(), Value::Bool(false));
    map.insert("error".to_string(), Value::String(err_msg.to_string()));
    println!("{}", serde_json::to_string(&Value::Object(map)).unwrap());
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Uso: astral-ad-ops <operacao> [--request-stdin | --request <json>]");
        eprintln!("Operações: provision, bind, demote, forensic, pki, host-prep");
        std::process::exit(1);
    }

    let operation = &args[1];
    let mut request_str = String::new();

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--request-stdin" {
            let _ = io::stdin().read_to_string(&mut request_str);
        } else if args[i] == "--request" && i + 1 < args.len() {
            request_str = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }

    let request_val: Value = if request_str.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_str(&request_str) {
            Ok(v) => v,
            Err(e) => {
                print_error_and_exit(&format!("JSON de requisição inválido: {}", e));
                return;
            }
        }
    };

    let root = Path::new("/");

    match operation.as_str() {
        "host-prep" | "prepare-host" => {
            match host_prep::prepare_host_packages(root) {
                Ok(msg) => print_json_and_exit(true, "message", Value::String(msg), 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        "provision" => {
            match provision_workflow::execute_workflow(&request_val, root) {
                Ok(data) => print_json_and_exit(true, "data", data, 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        "bind" => {
            match configure_bind(&request_val, root) {
                Ok(steps) => print_json_and_exit(true, "steps", serde_json::to_value(steps).unwrap(), 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        "demote" => {
            match dc_lifecycle::demote_dc(&request_val) {
                Ok(steps) => print_json_and_exit(true, "steps", serde_json::to_value(steps).unwrap(), 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        "forensic" => {
            match ad_forensics::execute_forensics(&request_val) {
                Ok(data) => print_json_and_exit(true, "data", data, 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        "pki" => {
            match pki_management::execute_pki_management(&request_val) {
                Ok(data) => print_json_and_exit(true, "data", data, 0),
                Err(e) => print_error_and_exit(&e),
            }
        }
        other => {
            print_error_and_exit(&format!("Operação desconhecida: {}", other));
        }
    }
}
