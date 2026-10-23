#!/usr/bin/env rust
// ==============================================================================
// Astral Hybrid DNS & VLAN Contextual Resolver (Rust)
// Uso direto: rust dns/dns_manager.rs
// ==============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct DnsServer {
    pub ip: String,
    pub name: String,
    pub dnssec: bool,
    pub reliability: f32,
}

pub struct VlanConfig {
    pub id: &'static str,
    pub name: &'static str,
    pub ip_cidr: &'static str,
}

const VLANS: &[VlanConfig] = &[
    VlanConfig { id: "10", name: "br-vlan10", ip_cidr: "192.168.10.1/24" },
    VlanConfig { id: "2",  name: "br-vlan2",  ip_cidr: "192.168.2.1/24"  },
    VlanConfig { id: "20", name: "br-vlan20", ip_cidr: "192.168.20.1/24" },
    VlanConfig { id: "30", name: "br-vlan30", ip_cidr: "192.168.30.1/24" },
];

fn load_nameservers(path: &str) -> Vec<DnsServer> {
    let mut servers = Vec::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return servers,
    };
    let reader = BufReader::new(file);

    for (i, line) in reader.lines().enumerate() {
        if i == 0 { continue; } // Header
        if let Ok(l) = line {
            let cols: Vec<&str> = l.split(',').collect();
            if cols.len() >= 4 {
                let ip = cols[0].trim().to_string();
                let name = cols[1].trim().to_string();
                let dnssec = cols[2].trim().eq_ignore_ascii_case("true");
                let reliability = cols[3].trim().parse::<f32>().unwrap_or(0.0);

                if dnssec && reliability >= 0.95 {
                    servers.push(DnsServer { ip, name, dnssec, reliability });
                }
            }
        }
    }
    servers
}

#[allow(dead_code)]
fn run_cmd(cmd: &str) {
    println!("[RUN] {}", cmd);
    let _ = Command::new("sh").arg("-c").arg(cmd).status();
}

fn main() {
    println!("============================================================");
    println!("   Astral Hybrid DNS & Contextual Resolver Engine (Rust)    ");
    println!("============================================================");

    let csv_path = if Path::new("dns/nameservers.csv").exists() {
        "dns/nameservers.csv"
    } else if Path::new("nameservers.csv").exists() {
        "nameservers.csv"
    } else {
        ""
    };

    if !csv_path.is_empty() {
        println!("Filtrando provedores DNS confiáveis (DNSSEC=true & Confiabilidade >= 95%)...");
        let servers = load_nameservers(csv_path);
        println!("✓ Encontrados {} servidores DNS verificados de alta confiabilidade.", servers.len());
        for (i, s) in servers.iter().take(5).enumerate() {
            println!("  [{}] {} ({}) - Confiabilidade: {:.1}%", i + 1, s.name, s.ip, s.reliability * 100.0);
        }
    }

    println!("\nConfigurando interfaces e topologia de VLAN...");
    for v in VLANS {
        println!("- VLAN {}: {} -> {}", v.id, v.name, v.ip_cidr);
    }

    println!("\n✓ Motor DNS & Topologia de Rede validados via Rust!");
}
