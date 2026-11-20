// ==============================================================================
// Astral AD & Hybrid DNS - TLS & Certificate Provisioning (Rust)
// ==============================================================================

use std::fs;
use std::path::Path;
use std::process::Command;
use crate::provision_system::atomic_write;

pub fn validate_tls_set(cert: &Path, key: &Path, ca: &Path, fqdn: &str) -> Result<(), String> {
    if !cert.is_file() || !key.is_file() || !ca.is_file() {
        return Err("Arquivos TLS (cert, key, ca) não encontrados.".to_string());
    }

    // Check expiration
    let checkend = Command::new("openssl")
        .args(["x509", "-in", cert.to_str().unwrap(), "-noout", "-checkend", "0"])
        .output()
        .map_err(|e| format!("Falha ao verificar expiração: {}", e))?;
    if !checkend.status.success() {
        return Err("O certificado TLS já expirou.".to_string());
    }

    // Verify chain and purpose
    let verify = Command::new("openssl")
        .args([
            "verify", "-purpose", "sslserver",
            "-verify_hostname", fqdn,
            "-CAfile", ca.to_str().unwrap(),
            cert.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("Falha ao verificar cadeia TLS: {}", e))?;
    if !verify.status.success() {
        let err = String::from_utf8_lossy(&verify.stderr);
        return Err(format!("Verificação de cadeia TLS falhou: {}", err));
    }

    // Compare public keys
    let pub_cert = Command::new("openssl")
        .args(["x509", "-in", cert.to_str().unwrap(), "-pubkey", "-noout"])
        .output()
        .map_err(|e| e.to_string())?;
    let pub_key = Command::new("openssl")
        .args(["pkey", "-in", key.to_str().unwrap(), "-passin", "pass:", "-pubout"])
        .output()
        .map_err(|e| e.to_string())?;

    if pub_cert.stdout.trim_ascii() != pub_key.stdout.trim_ascii() {
        return Err("A chave privada não corresponde ao certificado TLS fornecido.".to_string());
    }

    Ok(())
}

pub fn install_tls_files(root: &Path, cert_bytes: &[u8], key_bytes: &[u8], ca_bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let tls_dir = root.join("etc/samba/tls");
    fs::create_dir_all(&tls_dir).map_err(|e| format!("Falha ao criar {:?}: {}", tls_dir, e))?;

    let cert_path = tls_dir.join("dc.crt");
    let key_path = tls_dir.join("dc.key");
    let ca_path = tls_dir.join("ca.crt");

    atomic_write(&cert_path, cert_bytes, 0o644)?;
    atomic_write(&key_path, key_bytes, 0o600)?;
    atomic_write(&ca_path, ca_bytes, 0o644)?;

    Ok(vec![
        ("tls enabled".to_string(), "yes".to_string()),
        ("tls certfile".to_string(), cert_path.to_string_lossy().to_string()),
        ("tls keyfile".to_string(), key_path.to_string_lossy().to_string()),
        ("tls cafile".to_string(), ca_path.to_string_lossy().to_string()),
    ])
}
