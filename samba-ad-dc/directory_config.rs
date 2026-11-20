// ==============================================================================
// Astral AD & Hybrid DNS - Directory Configuration & Distro Profiles (Rust)
// ==============================================================================

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct DistroProfile {
    pub family: String,
    pub samba_unit: String,
    pub samba_conflicts: Vec<String>,
    pub bind_user: String,
    pub bind_group: String,
    pub bind_service: String,
    pub bind_work_dir: String,
    pub bind_cache: String,
    pub bind_options_file: String,
    pub named_conf: String,
    pub packages: Vec<String>,
}

impl DistroProfile {
    pub fn new(
        family: &str,
        samba_unit: &str,
        samba_conflicts: &[&str],
        bind_user: &str,
        bind_group: &str,
        bind_service: &str,
        bind_work_dir: &str,
        bind_options_file: &str,
        named_conf: &str,
        packages: &[&str],
    ) -> Self {
        Self {
            family: family.to_string(),
            samba_unit: samba_unit.to_string(),
            samba_conflicts: samba_conflicts.iter().map(|s| s.to_string()).collect(),
            bind_user: bind_user.to_string(),
            bind_group: bind_group.to_string(),
            bind_service: bind_service.to_string(),
            bind_work_dir: bind_work_dir.to_string(),
            bind_cache: bind_work_dir.to_string(),
            bind_options_file: bind_options_file.to_string(),
            named_conf: named_conf.to_string(),
            packages: packages.iter().map(|s| s.to_string()).collect(),
        }
    }
}

pub fn detect_distro_profile(root: &Path) -> DistroProfile {
    let os_release_path = root.join("etc/os-release");
    let mut os_data = HashMap::new();
    if let Ok(content) = fs::read_to_string(&os_release_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains('=') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim().to_uppercase();
            let val = parts.next().unwrap_or("").trim().trim_matches('"').trim_matches('\'').to_string();
            os_data.insert(key, val);
        }
    }

    let id = os_data.get("ID").cloned().unwrap_or_default().to_lowercase();
    let id_like = os_data.get("ID_LIKE").cloned().unwrap_or_default().to_lowercase();

    if id == "debian" || id_like.contains("debian") || id == "ubuntu" || id_like.contains("ubuntu") {
        DistroProfile::new(
            "debian",
            "samba-ad-dc",
            &["smbd", "nmbd", "winbind"],
            "bind",
            "bind",
            "named",
            "/var/cache/bind",
            "/etc/bind/named.conf.options",
            "/etc/bind/named.conf",
            &[
                "samba", "samba-ad-dc", "winbind", "libnss-winbind",
                "krb5-user", "smbclient", "ldb-tools", "python3-samba",
                "bind9", "bind9utils", "chrony",
            ],
        )
    } else if id == "arch" || id_like.contains("arch") {
        DistroProfile::new(
            "arch",
            "samba",
            &["smbd", "nmbd", "winbind"],
            "named",
            "named",
            "named",
            "/var/named",
            "/etc/named.conf",
            "/etc/named.conf",
            &["samba", "bind", "chrony", "krb5"],
        )
    } else if id.starts_with("opensuse") || id == "sles" || id == "sled" || id_like.contains("suse") {
        DistroProfile::new(
            "suse",
            "samba-ad-dc",
            &["smb", "nmb", "winbind"],
            "named",
            "named",
            "named",
            "/var/lib/named",
            "/etc/named.conf",
            "/etc/named.conf",
            &[
                "samba", "samba-ad-dc", "samba-client", "samba-winbind",
                "krb5-client", "bind", "bind-utils", "chrony",
            ],
        )
    } else {
        // RedHat / Fedora / CentOS / AlmaLinux / Rocky Linux
        DistroProfile::new(
            "redhat",
            "samba-dc",
            &["smb", "nmb", "winbind"],
            "named",
            "named",
            "named",
            "/var/named",
            "/etc/named.conf",
            "/etc/named.conf",
            &[
                "samba", "samba-dc", "samba-winbind", "samba-winbind-clients",
                "krb5-workstation", "ldb-tools", "bind", "bind-utils",
                "chrony", "python3-setproctitle", "policycoreutils-python-utils",
            ],
        )
    }
}

pub fn configure_global_catalog(server: Option<&str>, username: Option<&str>, password: Option<&str>) -> Result<serde_json::Value, String> {
    // Calls samba-tool or directory_config helper safely
    let mut cmd = Command::new("python3");
    cmd.arg("samba-ad-dc/directory_config.py");
    if let Some(srv) = server {
        cmd.arg("--server").arg(srv);
    }
    if let Some(user) = username {
        cmd.arg("--username").arg(user);
    }
    if let Some(pwd) = password {
        cmd.arg("--password").arg(pwd);
    }
    let output = cmd.output().map_err(|e| format!("Falha ao invocar directory_config: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    let val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Resposta invalida de directory_config: {}", e))?;
    Ok(val)
}
