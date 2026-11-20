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

use directory_config::detect_distro_profile;
use provision_system::atomic_write;

pub fn configure_bind(_request: &Value, root: &Path) -> Result<Vec<String>, String> {
    let mut steps = Vec::new();
    let profile = detect_distro_profile(root);

    // 1. Prepare directory permissions
    let bind_dir = root.join(profile.bind_work_dir.trim_start_matches('/'));
    fs::create_dir_all(&bind_dir).map_err(|e| e.to_string())?;
    let _ = Command::new("chown").args(["-R", &format!("{}:{}", profile.bind_user, profile.bind_group), bind_dir.to_str().unwrap()]).output();

    // 2. SELinux rules if enabled
    let selinux_enforce = root.join("sys/fs/selinux/enforce");
    if selinux_enforce.exists() {
        let _ = Command::new("semanage").args(["port", "-a", "-t", "dns_port_t", "-p", "udp", "5353"]).output();
        let _ = Command::new("semanage").args(["port", "-a", "-t", "dns_port_t", "-p", "tcp", "5353"]).output();
        steps.push("SELinux: porta 5353 rotulada como dns_port_t.".to_string());
    }

    // 3. AppArmor configuration if enabled
    let apparmor_named = root.join("etc/apparmor.d/local/usr.sbin.named");
    if apparmor_named.parent().map(|p| p.exists()).unwrap_or(false) {
        let rule = "/var/lib/samba/private/dns.keytab r,\n/var/lib/samba/private/named.conf r,\n/var/lib/samba/bind-dns/** rwk,\n";
        let _ = atomic_write(&apparmor_named, rule.as_bytes(), 0o644);
        let _ = Command::new("apparmor_parser").args(["-r", "/etc/apparmor.d/usr.sbin.named"]).output();
        steps.push("AppArmor: permissões locais do BIND atualizadas.".to_string());
    }

    // 4. Restart and enable BIND service
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
