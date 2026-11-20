// ==============================================================================
// Astral AD & Hybrid DNS - Multi-Distro Host Preparation (Rust)
// ==============================================================================

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::provision_system::atomic_write;

pub fn detect_distribution(os_release_path: &Path) -> (String, String, bool) {
    let mut data = HashMap::new();
    if let Ok(content) = fs::read_to_string(os_release_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains('=') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim().to_uppercase();
            let val = parts.next().unwrap_or("").trim().trim_matches('"').trim_matches('\'').to_string();
            data.insert(key, val);
        }
    }

    let distro = data.get("ID").cloned().unwrap_or_default().to_lowercase();
    let like = data.get("ID_LIKE").cloned().unwrap_or_default().to_lowercase();
    let version = data.get("VERSION_ID").cloned().unwrap_or_default();
    let major = version.split('.').next().unwrap_or("").to_string();

    let is_suse = distro.starts_with("opensuse") || distro == "sles" || distro == "sled" || like.contains("suse");
    if distro == "fedora" || distro == "arch" || distro == "archlinux" || distro == "ubuntu" || is_suse {
        return (distro, major, false);
    }

    let is_el = matches!(distro.as_str(), "rhel" | "almalinux" | "rocky" | "centos" | "ol" | "oracle")
        || like.contains("rhel")
        || like.contains("centos");

    (distro, major, is_el)
}

pub fn prepare_host_packages(root: &Path) -> Result<String, String> {
    let os_release = root.join("etc/os-release");
    let (distro, major, is_el) = detect_distribution(&os_release);

    let is_suse = distro.starts_with("opensuse") || distro == "sles" || distro == "sled" || distro.contains("suse");
    if distro == "fedora" || distro == "arch" || distro == "archlinux" || distro == "ubuntu" || is_suse {
        let msg = format!("{}: utiliza repositórios oficiais da distribuição (não requer pacotes Tranquil IT).", distro);
        println!("[OK] {}", msg);
        return Ok(msg);
    }

    if distro == "debian" {
        if major != "12" && major != "13" {
            return Err(format!("Debian versão {} não homologada para Tranquil IT (suporte: Debian 12 ou 13).", major));
        }

        println!("[PREP] Configurando repositório oficial Tranquil IT Samba 4.24 para Debian {}...", major);
        let keyring = root.join("usr/share/keyrings/tissamba.gpg");
        if let Some(parent) = keyring.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let curl_out = Command::new("curl")
            .args(["-fsSL", "https://samba.tranquil.it/tissamba-pubkey.gpg"])
            .output()
            .map_err(|e| format!("Falha ao baixar chave GPG da Tranquil IT: {}", e))?;
        if !curl_out.status.success() {
            return Err("Download da chave GPG da Tranquil IT falhou.".to_string());
        }

        // gpg --dearmor
        let mut gpg = Command::new("gpg")
            .args(["--dearmor", "-o", keyring.to_str().unwrap(), "--yes"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Falha ao desarmar chave GPG: {}", e))?;
        if let Some(mut stdin) = gpg.stdin.take() {
            let _ = stdin.write_all(&curl_out.stdout);
        }
        let gpg_res = gpg.wait().map_err(|e| e.to_string())?;
        if !gpg_res.success() {
            return Err("Conversão de chave GPG falhou.".to_string());
        }

        let codename = if major == "13" { "trixie" } else { "bookworm" };
        let repo_line = format!(
            "deb [signed-by=/usr/share/keyrings/tissamba.gpg] https://samba.tranquil.it/debian/samba-4.24/ {} main\n",
            codename
        );
        let list_file = root.join("etc/apt/sources.list.d/tissamba.list");
        atomic_write(&list_file, repo_line.as_bytes(), 0o644)?;

        // apt-get update & install
        println!("[PREP] Atualizando índices APT e instalando pacotes...");
        let _ = Command::new("apt-get").arg("update").output();
        let install_res = Command::new("apt-get")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .args([
                "install", "-y",
                "samba", "samba-ad-dc", "winbind", "libnss-winbind",
                "krb5-user", "smbclient", "ldb-tools", "python3-samba",
                "bind9", "bind9utils", "chrony",
            ])
            .output()
            .map_err(|e| format!("Falha ao instalar pacotes via apt: {}", e))?;
        if !install_res.status.success() {
            return Err(format!("apt-get install falhou: {}", String::from_utf8_lossy(&install_res.stderr)));
        }

        // Mask avahi-daemon to prevent conflict on port 5353
        let _ = Command::new("systemctl").args(["stop", "avahi-daemon.service", "avahi-daemon.socket"]).output();
        let _ = Command::new("systemctl").args(["mask", "avahi-daemon.service", "avahi-daemon.socket"]).output();

        let msg = format!("Debian {} configurado com sucesso via Tranquil IT.", major);
        println!("[OK] {}", msg);
        return Ok(msg);
    }

    if is_el {
        if major != "9" && major != "10" {
            return Err(format!("Enterprise Linux versão {} não suportada (suporte: EL9 ou EL10).", major));
        }

        println!("[PREP] Configurando Tranquil IT e CRB/EPEL para EL{}...", major);
        let key_url = format!("https://samba.tranquil.it/RPM-GPG-KEY-TISSAMBA-{}", major);
        let _ = Command::new("rpm").args(["--import", &key_url]).output();

        let repo_content = format!(
            "[tissamba]\nname=Tranquil IT Samba 4.24 (EL{})\nbaseurl=https://samba.tranquil.it/redhat{}/samba-4.24/\ngpgcheck=1\ngpgkey={}\nenabled=1\n",
            major, major, key_url
        );
        let repo_path = root.join("etc/yum.repos.d/tissamba.repo");
        atomic_write(&repo_path, repo_content.as_bytes(), 0o644)?;

        let _ = Command::new("dnf").args(["config-manager", "--set-enabled", "crb"]).output();
        let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();

        let install_res = Command::new("dnf")
            .args([
                "install", "-y",
                "samba", "samba-dc", "samba-winbind", "samba-winbind-clients",
                "krb5-workstation", "ldb-tools", "bind", "bind-utils",
                "chrony", "python3-setproctitle", "policycoreutils-python-utils",
            ])
            .output()
            .map_err(|e| format!("Falha ao instalar pacotes via dnf: {}", e))?;
        if !install_res.status.success() {
            return Err(format!("dnf install falhou: {}", String::from_utf8_lossy(&install_res.stderr)));
        }

        let msg = format!("Enterprise Linux {} preparado com sucesso com Tranquil IT.", major);
        println!("[OK] {}", msg);
        return Ok(msg);
    }

    Err(format!("Distribuição {} {} não reconhecida para preparação.", distro, major))
}
