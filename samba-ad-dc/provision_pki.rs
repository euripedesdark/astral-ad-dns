// ==============================================================================
// Astral AD & Hybrid DNS - Step-CA & PKI Provisioning (Rust)
// ==============================================================================

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::provision_system::atomic_write;

pub fn find_step_cli() -> Option<PathBuf> {
    for name in &["step-cli", "step"] {
        if let Ok(output) = Command::new("which").arg(name).output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }
    }
    None
}

pub fn configure_step_ca(
    root: &Path,
    realm: &str,
    hostname_fqdn: &str,
    host_ip: &str,
    ca_port: u16,
    password: &str,
) -> Result<String, String> {
    // 1. Stop existing step-ca before re-initialization
    let _ = Command::new("systemctl").args(["stop", "step-ca"]).output();

    let step_dir = root.join("etc/step-ca");
    fs::create_dir_all(&step_dir).map_err(|e| format!("Falha ao criar {:?}: {}", step_dir, e))?;

    let pwd_file = step_dir.join("password.txt");
    atomic_write(&pwd_file, password.as_bytes(), 0o600)?;

    let step_bin = find_step_cli().ok_or("step-cli não encontrado no sistema.")?;

    // 2. Initialize step-ca
    let ca_json = step_dir.join("config/ca.json");
    if !ca_json.exists() {
        let mut init_cmd = Command::new(&step_bin);
        init_cmd.env("STEPPATH", &step_dir);
        init_cmd.args([
            "ca", "init",
            "--name", &format!("{} Root CA", realm),
            "--dns", hostname_fqdn,
            "--dns", host_ip,
            "--dns", &format!("ca.{}", realm.to_lowercase()),
            "--address", &format!("{}:{}", host_ip, ca_port),
            "--provisioner", &format!("admin@{}", realm.to_lowercase()),
            "--password-file", pwd_file.to_str().unwrap(),
            "--deployment-type", "standalone",
        ]);
        let output = init_cmd.output().map_err(|e| format!("Falha ao inicializar CA Step: {}", e))?;
        if !output.status.success() {
            return Err(format!("step ca init falhou: {}", String::from_utf8_lossy(&output.stderr)));
        }
    }

    // 3. Write systemd unit
    let service_content = format!(
        "[Unit]\nDescription=Astral Step Certificate Authority\nAfter=network-online.target\n\n[Service]\nUser=root\nEnvironment=STEPPATH={}\nWorkingDirectory={}\nExecStart=/usr/bin/step-ca {}/config/ca.json --password-file {}\nRestart=on-failure\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n",
        step_dir.display(),
        step_dir.display(),
        step_dir.display(),
        pwd_file.display()
    );
    let unit_path = root.join("etc/systemd/system/step-ca.service");
    atomic_write(&unit_path, service_content.as_bytes(), 0o644)?;

    let _ = Command::new("systemctl").arg("daemon-reload").output();
    let _ = Command::new("systemctl").args(["enable", "step-ca"]).output();
    let _ = Command::new("systemctl").args(["restart", "step-ca"]).output();

    // 4. Issue certificate for Samba AD LDAPS
    let tls_dir = root.join("etc/samba/tls");
    fs::create_dir_all(&tls_dir).map_err(|e| format!("Falha ao criar {:?}: {}", tls_dir, e))?;
    let cert_file = tls_dir.join("dc.crt");
    let key_file = tls_dir.join("dc.key");
    let ca_file = tls_dir.join("ca.crt");

    // Copy root CA
    let root_crt = step_dir.join("certs/root_ca.crt");
    if root_crt.exists() {
        let _ = fs::copy(&root_crt, &ca_file);
    }

    let mut cert_cmd = Command::new(&step_bin);
    cert_cmd.env("STEPPATH", &step_dir);
    cert_cmd.args([
        "ca", "certificate",
        hostname_fqdn,
        cert_file.to_str().unwrap(),
        key_file.to_str().unwrap(),
        "--ca-url", &format!("https://{}:{}", host_ip, ca_port),
        "--root", root_crt.to_str().unwrap(),
        "--password-file", pwd_file.to_str().unwrap(),
        "--provisioner", &format!("admin@{}", realm.to_lowercase()),
        "--force",
    ]);
    let cert_out = cert_cmd.output();
    if let Ok(res) = cert_out {
        if !res.status.success() {
            eprintln!("[WARN] Aviso ao emitir certificado inicial: {}", String::from_utf8_lossy(&res.stderr));
        }
    }

    Ok(format!("https://{}:{}", host_ip, ca_port))
}
