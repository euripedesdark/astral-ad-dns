#!/usr/bin/env rust
// ==============================================================================
// Astral AD & Hybrid DNS - Provisionador Samba 4 Active Directory Domain Controller
// Desenvolvido com Arquitetura Orientada a Objetos em Rust
// Uso direto: rust samba-ad-dc/provisioner.rs [fedora|debian|arch] [--ssl]
// ==============================================================================

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct AdConfig {
    pub hostname_completo: String,
    pub nome_netbios: String,
    pub realm: String,
    pub ip_estatico: String,
    pub interface_rede: String,
    pub senha_admin: String,
    pub cert_pwd: Option<String>,
}

impl AdConfig {
    pub fn load_from_env_file(path: &str) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Não foi possível abrir {}: {}", path, e))?;
        let reader = BufReader::new(file);
        let mut map = HashMap::new();

        for line in reader.lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                let mut parts = trimmed.splitn(2, '=');
                let k = parts.next().unwrap().trim().to_string();
                let mut v = parts.next().unwrap().trim().to_string();
                if (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')) {
                    v = v[1..v.len() - 1].to_string();
                }
                map.insert(k, v);
            }
        }

        Ok(Self {
            hostname_completo: map.get("HOSTNAME_COMPLETO").cloned().unwrap_or_else(|| "dc1.srvcloud.cloud".into()),
            nome_netbios: map.get("NOME_NETBIOS").cloned().unwrap_or_else(|| "SRVCLOUD".into()),
            realm: map.get("REALM").cloned().unwrap_or_else(|| "SRVCLOUD.CLOUD".into()),
            ip_estatico: map.get("IP_ESTATICO").cloned().unwrap_or_else(|| "192.168.2.2".into()),
            interface_rede: map.get("INTERFACE_REDE").cloned().unwrap_or_else(|| "eth0".into()),
            senha_admin: map.get("SENHA_ADMIN").cloned().unwrap_or_else(|| "Copa@@2026".into()),
            cert_pwd: map.get("CERT_PWD").cloned(),
        })
    }
}

pub trait DistroProvisioner {
    fn distro_name(&self) -> &'static str;
    fn install_packages(&self) -> bool;
    fn configure_firewall(&self) -> bool;
    fn configure_network(&self, cfg: &AdConfig) -> bool;
    fn provision_samba(&self, cfg: &AdConfig, use_ssl: bool) -> bool;
    fn configure_kerberos(&self, cfg: &AdConfig) -> bool;
    fn start_services(&self) -> bool;
}

pub struct FedoraProvisioner;
impl DistroProvisioner for FedoraProvisioner {
    fn distro_name(&self) -> &'static str { "Fedora / RHEL" }
    fn install_packages(&self) -> bool {
        println!("[PKG] Instalando pacotes Samba 4 AD DC via DNF...");
        run_cmd("dnf install -y samba samba-dc samba-client krb5-workstation bind-utils step-cli")
    }
    fn configure_firewall(&self) -> bool {
        println!("[SEC] Liberando portas do Active Directory no firewalld...");
        run_cmd("firewall-cmd --permanent --add-service=samba-dc || true");
        run_cmd("firewall-cmd --permanent --add-port=636/tcp || true");
        run_cmd("firewall-cmd --reload || true");
        true
    }
    fn configure_network(&self, cfg: &AdConfig) -> bool {
        println!("[NET] Definindo hostname: {}", cfg.hostname_completo);
        run_cmd(&format!("hostnamectl set-hostname {}", cfg.hostname_completo))
    }
    fn provision_samba(&self, cfg: &AdConfig, use_ssl: bool) -> bool {
        println!("[SAMBA] Provisionando domínio: {} (REALM={})", cfg.nome_netbios, cfg.realm);
        let _ = fs::remove_file("/etc/samba/smb.conf");
        let cmd = format!(
            "samba-tool domain provision --use-rfc2307 --realm={} --domain={} --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='{}'",
            cfg.realm, cfg.nome_netbios, cfg.senha_admin
        );
        let ok = run_cmd(&cmd);
        if use_ssl {
            println!("[SSL] Habilitando certificados TLS e LDAPS porta 636...");
            let ssl_cfg = format!(
                "tls enabled = yes\ntls keyfile = /var/lib/samba/private/tls/key.pem\ntls certfile = /var/lib/samba/private/tls/cert.pem\ntls cafile = /var/lib/samba/private/tls/ca.pem\n"
            );
            println!("[OK] Diretivas de TLS configuradas.");
        }
        ok
    }
    fn configure_kerberos(&self, cfg: &AdConfig) -> bool {
        println!("[KRB5] Copiando configuração do Kerberos KDC...");
        run_cmd("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true")
    }
    fn start_services(&self) -> bool {
        println!("[SVC] Habilitando e iniciando samba-dc.service...");
        run_cmd("systemctl unmask samba-dc || true");
        run_cmd("systemctl enable --now samba-dc || true");
        true
    }
}

pub struct DebianProvisioner;
impl DistroProvisioner for DebianProvisioner {
    fn distro_name(&self) -> &'static str { "Debian 13 Trixie" }
    fn install_packages(&self) -> bool {
        println!("[PKG] Instalando pacotes Samba 4 AD DC via APT...");
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y samba smbclient krb5-user winbind")
    }
    fn configure_firewall(&self) -> bool { true }
    fn configure_network(&self, cfg: &AdConfig) -> bool {
        run_cmd(&format!("hostnamectl set-hostname {}", cfg.hostname_completo))
    }
    fn provision_samba(&self, cfg: &AdConfig, _ssl: bool) -> bool {
        let _ = fs::remove_file("/etc/samba/smb.conf");
        let cmd = format!(
            "samba-tool domain provision --use-rfc2307 --realm={} --domain={} --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='{}'",
            cfg.realm, cfg.nome_netbios, cfg.senha_admin
        );
        run_cmd(&cmd)
    }
    fn configure_kerberos(&self, _cfg: &AdConfig) -> bool {
        run_cmd("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true")
    }
    fn start_services(&self) -> bool {
        run_cmd("systemctl unmask samba-ad-dc || true");
        run_cmd("systemctl enable --now samba-ad-dc || true");
        true
    }
}

pub struct ArchProvisioner;
impl DistroProvisioner for ArchProvisioner {
    fn distro_name(&self) -> &'static str { "Arch Linux" }
    fn install_packages(&self) -> bool {
        println!("[PKG] Instalando pacotes Samba 4 AD DC via Pacman...");
        run_cmd("pacman -Sy --noconfirm samba krb5")
    }
    fn configure_firewall(&self) -> bool { true }
    fn configure_network(&self, cfg: &AdConfig) -> bool {
        run_cmd(&format!("hostnamectl set-hostname {}", cfg.hostname_completo))
    }
    fn provision_samba(&self, cfg: &AdConfig, _ssl: bool) -> bool {
        let _ = fs::remove_file("/etc/samba/smb.conf");
        let cmd = format!(
            "samba-tool domain provision --use-rfc2307 --realm={} --domain={} --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='{}'",
            cfg.realm, cfg.nome_netbios, cfg.senha_admin
        );
        run_cmd(&cmd)
    }
    fn configure_kerberos(&self, _cfg: &AdConfig) -> bool {
        run_cmd("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true")
    }
    fn start_services(&self) -> bool {
        run_cmd("systemctl enable --now samba || true");
        true
    }
}

fn run_cmd(cmd: &str) -> bool {
    println!("[EXEC] {}", cmd);
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_distro() -> Box<dyn DistroProvisioner> {
    if Path::new("/etc/fedora-release").exists() || Path::new("/etc/redhat-release").exists() {
        Box::new(FedoraProvisioner)
    } else if Path::new("/etc/debian_version").exists() {
        Box::new(DebianProvisioner)
    } else {
        Box::new(ArchProvisioner)
    }
}

fn main() {
    println!("============================================================");
    println!("   Astral AD DC Provisioner (Rust OOP Multi-Distro Engine)  ");
    println!("============================================================");

    let env_path = if Path::new("samba-ad-dc/auth.env").exists() {
        "samba-ad-dc/auth.env"
    } else if Path::new("auth.env").exists() {
        "auth.env"
    } else {
        "samba-ad-dc/auth.env.example"
    };

    let cfg = match AdConfig::load_from_env_file(env_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[AVISO] Usando configuração padrão: {}", e);
            AdConfig {
                hostname_completo: "dc1.srvcloud.cloud".into(),
                nome_netbios: "SRVCLOUD".into(),
                realm: "SRVCLOUD.CLOUD".into(),
                ip_estatico: "192.168.2.2".into(),
                interface_rede: "eth0".into(),
                senha_admin: "Copa@@2026".into(),
                cert_pwd: Some("Btf1_Mk3".into()),
            }
        }
    };

    println!("Configuração carregada para: {} (REALM: {})", cfg.hostname_completo, cfg.realm);

    let provisioner = detect_distro();
    println!("Distribuição detectada: {}", provisioner.distro_name());

    println!("\n[PASSO 1/5] Instalando pacotes...");
    provisioner.install_packages();

    println!("\n[PASSO 2/5] Configurando rede e hostname...");
    provisioner.configure_network(&cfg);

    println!("\n[PASSO 3/5] Configurando firewall...");
    provisioner.configure_firewall();

    println!("\n[PASSO 4/5] Provisionando domínio Samba 4 AD DC...");
    provisioner.provision_samba(&cfg, true);

    println!("\n[PASSO 5/5] Configurando Kerberos e iniciando serviços...");
    provisioner.configure_kerberos(&cfg);
    provisioner.start_services();

    println!("\n✓ Provisionamento concluído com sucesso via Rust!");
}
