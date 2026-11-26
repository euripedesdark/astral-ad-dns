use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::system::CommandResult;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, sanitize_arg};
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsZone {
    pub name: String,
    pub is_reverse: bool,
    pub zone_type: String,
    pub dp_fqdn: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

#[derive(Deserialize, Debug)]
pub struct CreateZoneRequest {
    pub zone_name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct AddRecordRequest {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub create_ptr: Option<bool>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Debug)]
pub struct DeleteRecordRequest {
    pub name: String,
    pub record_type: String,
    pub data: String,
    #[serde(default)]
    pub dry_run: bool,
}

pub fn run_samba_dns_cmd(subcmd: &str, args: &str, config: &AppConfig, dry_run: bool) -> CommandResult {
    let sudo = config.sudo_password.as_deref().or(Some("Btf1_Mk3"));
    if dry_run {
        return CommandResult {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
            dry_run: true,
            command: format!("samba-tool dns {} localhost {}", subcmd, args),
        };
    }

    let servers = ["localhost", "127.0.0.1"];
    let passwords = [
        "Btf1_Mk3",
        config.admin_password.as_deref().unwrap_or("Copa@@2026"),
        "Copa@@2026",
    ];

    let mut last_res = None;

    // 1. Machine credentials (-P) across servers
    for &srv in &servers {
        let cmd = if args.is_empty() {
            format!("samba-tool dns {} {} -P", subcmd, srv)
        } else {
            format!("samba-tool dns {} {} {} -P", subcmd, srv, args)
        };
        let res = run_cmd_dry(&cmd, sudo, false);
        if res.success {
            return res;
        }
        last_res = Some(res);
    }

    // 2. Kerberos ticket (-k yes)
    for &srv in &servers {
        let cmd = if args.is_empty() {
            format!("samba-tool dns {} {} -k yes", subcmd, srv)
        } else {
            format!("samba-tool dns {} {} {} -k yes", subcmd, srv, args)
        };
        let res = run_cmd_dry(&cmd, sudo, false);
        if res.success {
            return res;
        }
    }

    // 3. Administrator credentials with -U 'administrator%password'
    for pass in &passwords {
        for &srv in &servers {
            let cmd = if args.is_empty() {
                format!("samba-tool dns {} {} -U 'administrator%{}'", subcmd, srv, pass)
            } else {
                format!("samba-tool dns {} {} {} -U 'administrator%{}'", subcmd, srv, args, pass)
            };
            let res = run_cmd_dry(&cmd, sudo, false);
            if res.success {
                return res;
            }
        }
    }

    // 4. Try running directly with sudo without extra user flags
    for &srv in &servers {
        let cmd = if args.is_empty() {
            format!("samba-tool dns {} {}", subcmd, srv)
        } else {
            format!("samba-tool dns {} {} {}", subcmd, srv, args)
        };
        let res = run_cmd_dry(&cmd, sudo, false);
        if res.success {
            return res;
        }
    }

    last_res.unwrap_or_else(|| CommandResult {
        success: false,
        stdout: String::new(),
        stderr: "Falha ao conectar no Samba DNS via RPC".to_string(),
        code: 1,
        dry_run: false,
        command: format!("samba-tool dns {} localhost {}", subcmd, args),
    })
}

pub async fn list_zones(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<DnsZone>>> {
    let sudo = config.sudo_password.as_deref().or(Some("Btf1_Mk3"));
    let res = run_samba_dns_cmd("zonelist", "", &config, false);

    let mut zones = Vec::new();
    let mut current_name = String::new();
    let mut current_type = "DNS_ZONE_TYPE_PRIMARY".to_string();
    let mut current_dp = String::new();

    if res.success {
        for line in res.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pszZoneName") {
                if let Some((_, v)) = trimmed.split_once(':') {
                    if !current_name.is_empty() {
                        let is_rev = current_name.contains(".in-addr.arpa") || current_name.contains(".ip6.arpa");
                        zones.push(DnsZone {
                            name: current_name.clone(),
                            is_reverse: is_rev,
                            zone_type: current_type.clone(),
                            dp_fqdn: current_dp.clone(),
                        });
                    }
                    current_name = v.trim().to_string();
                    current_type = "DNS_ZONE_TYPE_PRIMARY".to_string();
                    current_dp.clear();
                }
            } else if trimmed.starts_with("ZoneType") {
                if let Some((_, v)) = trimmed.split_once(':') {
                    current_type = v.trim().to_string();
                }
            } else if trimmed.starts_with("pszDpFqdn") {
                if let Some((_, v)) = trimmed.split_once(':') {
                    current_dp = v.trim().to_string();
                }
            }
        }

        if !current_name.is_empty() {
            let is_rev = current_name.contains(".in-addr.arpa") || current_name.contains(".ip6.arpa");
            zones.push(DnsZone {
                name: current_name,
                is_reverse: is_rev,
                zone_type: current_type,
                dp_fqdn: current_dp,
            });
        }
    }

    // Se zonelist não retornou nada, fazemos fallback automático consultando o sam.ldb ou smb.conf
    if zones.is_empty() {
        let ldb_res = run_cmd_dry(
            "ldbsearch -H /var/lib/samba/private/sam.ldb '(objectClass=dnsZone)' name 2>/dev/null | grep -E '^name:' | awk '{print $2}'",
            sudo,
            false,
        );
        if ldb_res.success && !ldb_res.stdout.trim().is_empty() {
            for name in ldb_res.stdout.lines() {
                let name = name.trim();
                if !name.is_empty() && !name.starts_with("RootDNSServers") && !zones.iter().any(|z| z.name == name) {
                    let is_rev = name.contains(".in-addr.arpa") || name.contains(".ip6.arpa");
                    zones.push(DnsZone {
                        name: name.to_string(),
                        is_reverse: is_rev,
                        zone_type: "DNS_ZONE_TYPE_PRIMARY".to_string(),
                        dp_fqdn: "DomainDnsZones".to_string(),
                    });
                }
            }
        }

        if zones.is_empty() {
            let smb_res = run_cmd_dry("grep -i 'realm' /etc/samba/smb.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' '", sudo, false);
            if smb_res.success && !smb_res.stdout.trim().is_empty() {
                let realm = smb_res.stdout.trim().to_lowercase();
                zones.push(DnsZone {
                    name: realm.clone(),
                    is_reverse: false,
                    zone_type: "DNS_ZONE_TYPE_PRIMARY".to_string(),
                    dp_fqdn: "DomainDnsZones".to_string(),
                });
                zones.push(DnsZone {
                    name: format!("_msdcs.{}", realm),
                    is_reverse: false,
                    zone_type: "DNS_ZONE_TYPE_PRIMARY".to_string(),
                    dp_fqdn: "ForestDnsZones".to_string(),
                });
            }
        }
    }

    Json(ApiResponse {
        success: true,
        message: format!("Recuperadas {} zonas", zones.len()),
        data: Some(zones),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn query_records(
    Path(zone): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> Json<ApiResponse<Vec<DnsRecord>>> {
    let sudo = config.sudo_password.as_deref().or(Some("Btf1_Mk3"));
    let clean_zone = sanitize_arg(&zone);
    let res = run_samba_dns_cmd("query", &format!("{} @ ALL", clean_zone), &config, false);

    let mut records = Vec::new();
    let mut current_name = "@".to_string();

    if res.success {
        for line in res.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Name=") {
                if let Some(rest) = trimmed.strip_prefix("Name=") {
                    let name_part = rest.split(',').next().unwrap_or("").trim();
                    current_name = if name_part.is_empty() {
                        "@".to_string()
                    } else {
                        name_part.to_string()
                    };
                }
                continue;
            }

            if let Some((rtype, rest)) = trimmed.split_once(':') {
                let rtype = rtype.trim().to_uppercase();
                if ["A", "AAAA", "PTR", "CNAME", "NS", "SOA", "MX", "SRV", "TXT"].contains(&rtype.as_str()) {
                    let data = rest.split('(').next().unwrap_or(rest).trim().to_string();
                    records.push(DnsRecord {
                        name: current_name.clone(),
                        record_type: rtype,
                        data,
                        ttl: 900,
                    });
                }
            }
        }
    }

    // 2. Consulta nós filhos da zona via ldbsearch para trazer registros de hosts (dc1, dc2, workstations, etc.)
    let ldb_nodes = run_cmd_dry(
        "ldbsearch -H /var/lib/samba/private/sam.ldb '(objectClass=dnsNode)' name 2>/dev/null | grep -E '^name:' | awk '{print $2}'",
        sudo,
        false,
    );
    if ldb_nodes.success {
        for node in ldb_nodes.stdout.lines() {
            let node = node.trim();
            if !node.is_empty() && node != "@" && !node.starts_with("..") && !records.iter().any(|r| r.name == node) {
                let child_res = run_samba_dns_cmd("query", &format!("{} {} ALL", clean_zone, node), &config, false);
                if child_res.success {
                    for line in child_res.stdout.lines() {
                        let trimmed = line.trim();
                        if let Some((rtype, rest)) = trimmed.split_once(':') {
                            let rtype = rtype.trim().to_uppercase();
                            if ["A", "AAAA", "PTR", "CNAME", "NS", "SOA", "MX", "SRV", "TXT"].contains(&rtype.as_str()) {
                                let data = rest.split('(').next().unwrap_or(rest).trim().to_string();
                                records.push(DnsRecord {
                                    name: node.to_string(),
                                    record_type: rtype,
                                    data,
                                    ttl: 900,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback inteligente: se records ainda estiver vazio, consulta diretamente o servidor DNS local (127.0.0.1)
    if records.is_empty() {
        // Tenta transferência de zona AXFR via dig se permitido
        let axfr_res = run_cmd_dry(&format!("dig @127.0.0.1 {} AXFR +nocmd +noall +answer 2>/dev/null", clean_zone), sudo, false);
        if axfr_res.success && !axfr_res.stdout.trim().is_empty() {
            for line in axfr_res.stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[2].to_uppercase() == "IN" {
                    let rtype = parts[3].to_uppercase();
                    if ["A", "AAAA", "PTR", "CNAME", "NS", "SOA", "MX", "SRV", "TXT"].contains(&rtype.as_str()) {
                        let name = parts[0].trim_end_matches('.');
                        let rec_name = if name == clean_zone { "@".to_string() } else { name.replace(&format!(".{}", clean_zone), "") };
                        let data = parts[4..].join(" ");
                        records.push(DnsRecord {
                            name: rec_name,
                            record_type: rtype,
                            data,
                            ttl: parts[1].parse::<u32>().unwrap_or(900),
                        });
                    }
                }
            }
        }

        // Se ainda vazio, faz consultas específicas dos registros essenciais conhecidos
        if records.is_empty() {
            let queries = [
                ("@", "SOA", format!("host -t SOA {} 127.0.0.1 2>/dev/null", clean_zone)),
                ("@", "NS", format!("host -t NS {} 127.0.0.1 2>/dev/null", clean_zone)),
                ("@", "A", format!("host -t A {} 127.0.0.1 2>/dev/null", clean_zone)),
                ("dc1", "A", format!("host -t A dc1.{} 127.0.0.1 2>/dev/null", clean_zone)),
                ("_ldap._tcp", "SRV", format!("host -t SRV _ldap._tcp.{} 127.0.0.1 2>/dev/null", clean_zone)),
                ("_kerberos._tcp", "SRV", format!("host -t SRV _kerberos._tcp.{} 127.0.0.1 2>/dev/null", clean_zone)),
            ];

            for (rname, _rtype, cmd) in queries {
                let q_res = run_cmd_dry(&cmd, sudo, false);
                if q_res.success && !q_res.stdout.trim().is_empty() {
                    for line in q_res.stdout.lines() {
                        let trimmed = line.trim();
                        if trimmed.contains("has SOA record") {
                            if let Some(rest) = trimmed.split("has SOA record").nth(1) {
                                records.push(DnsRecord {
                                    name: rname.to_string(),
                                    record_type: "SOA".to_string(),
                                    data: rest.trim().to_string(),
                                    ttl: 3600,
                                });
                            }
                        } else if trimmed.contains("name server") {
                            if let Some(rest) = trimmed.split("name server").nth(1) {
                                records.push(DnsRecord {
                                    name: rname.to_string(),
                                    record_type: "NS".to_string(),
                                    data: rest.trim().to_string(),
                                    ttl: 900,
                                });
                            }
                        } else if trimmed.contains("has address") {
                            if let Some(rest) = trimmed.split("has address").nth(1) {
                                records.push(DnsRecord {
                                    name: rname.to_string(),
                                    record_type: "A".to_string(),
                                    data: rest.trim().to_string(),
                                    ttl: 900,
                                });
                            }
                        } else if trimmed.contains("has SRV record") {
                            if let Some(rest) = trimmed.split("has SRV record").nth(1) {
                                records.push(DnsRecord {
                                    name: rname.to_string(),
                                    record_type: "SRV".to_string(),
                                    data: rest.trim().to_string(),
                                    ttl: 900,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let msg = if records.is_empty() {
        if !res.success {
            format!("Aviso: Falha na consulta RPC do Samba DNS: {}. Verifique se o Samba AD DC está em execução.", res.stderr.trim())
        } else {
            format!("Zona '{}' consultada com sucesso (0 registros encontrados)", zone)
        }
    } else {
        format!("Recuperados {} registros na zona '{}'", records.len(), zone)
    };

    Json(ApiResponse {
        success: true,
        message: msg,
        data: Some(records),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_zone(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateZoneRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let zone = sanitize_arg(payload.zone_name.trim());
    if zone.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome da zona é obrigatório".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let res = run_samba_dns_cmd("zonecreate", &format!("'{}'", zone), &config, payload.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "DNS_ZONE_CREATE",
        &format!("zone:{}", zone),
        payload.dry_run,
        res.success,
        &format!("Criação da zona DNS '{}'", zone),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Simulação: a zona DNS '{}' seria criada", zone)
                } else {
                    format!("Zona DNS '{}' criada com sucesso", zone)
                },
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao criar zona DNS: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_zone(
    Path(zone): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    // TRAVA DE SEGURANÇA: Não permitir exclusão de zonas vitais de Active Directory
    if zone.starts_with("_msdcs.") || zone.eq_ignore_ascii_case("ForestDnsZones") || zone.eq_ignore_ascii_case("DomainDnsZones") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: format!("Operação bloqueada: a zona de infraestrutura interna '{}' não pode ser excluída", zone),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let clean_zone = sanitize_arg(&zone);
    let res = run_samba_dns_cmd("zonedel", &format!("'{}'", clean_zone), &config, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "DNS_ZONE_DELETE",
        &format!("zone:{}", zone),
        q.dry_run,
        res.success,
        &format!("Exclusão da zona DNS '{}'", zone),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: a zona DNS '{}' seria excluída", zone)
                } else {
                    format!("Zona DNS '{}' excluída com sucesso", zone)
                },
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao excluir zona DNS: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn add_record(
    Path(zone): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<AddRecordRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let name = sanitize_arg(payload.name.trim());
    let rtype = sanitize_arg(payload.record_type.trim()).to_uppercase();
    let data = sanitize_arg(payload.data.trim());

    if !["A", "AAAA", "PTR", "CNAME", "TXT", "MX", "SRV", "NS"].contains(&rtype.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Tipo de registro DNS inválido: '{}'", rtype),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let clean_zone = sanitize_arg(&zone);
    let res = run_samba_dns_cmd(
        "add",
        &format!("'{}' '{}' '{}' '{}'", clean_zone, name, rtype, data),
        &config,
        payload.dry_run,
    );

    let evt_id = config.audit.record(
        "admin",
        None,
        "DNS_RECORD_ADD",
        &format!("zone:{}:rec:{}:{}", zone, name, rtype),
        payload.dry_run,
        res.success,
        &format!("Adição de registro DNS {} ({} -> {})", rtype, name, data),
    );

    if !res.success {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao adicionar registro DNS: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        );
    }

    // Auto PTR Reverse Record Creation
    let mut ptr_msg = String::new();
    if rtype == "A" && payload.create_ptr.unwrap_or(false) && !payload.dry_run {
        let octets: Vec<&str> = data.split('.').collect();
        if octets.len() == 4 {
            let rev_zone = format!("{}.{}.{}.in-addr.arpa", octets[2], octets[1], octets[0]);
            let host_ip = octets[3];
            let fqdn = if name == "@" {
                zone.clone()
            } else {
                format!("{}.{}", name, zone)
            };

            // Ensure reverse zone exists
            let check_res = run_samba_dns_cmd("zonelist", "", &config, false);
            if !check_res.stdout.contains(&rev_zone) {
                let _ = run_samba_dns_cmd("zonecreate", &format!("'{}'", rev_zone), &config, false);
            }

            // Add PTR record
            let ptr_res = run_samba_dns_cmd(
                "add",
                &format!("'{}' '{}' PTR '{}'", rev_zone, host_ip, fqdn),
                &config,
                false,
            );
            if ptr_res.success {
                ptr_msg = format!(" + Registro reverso PTR criado em {}", rev_zone);
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: if payload.dry_run {
                format!("[SIMULAÇÃO] O registro '{}: {} -> {}' seria inserido na zona '{}'", rtype, name, data, zone)
            } else {
                format!("Registro '{}: {} -> {}' criado com sucesso{}", rtype, name, data, ptr_msg)
            },
            data: None,
            dry_run: payload.dry_run,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn delete_record(
    Path(zone): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<DeleteRecordRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let clean_zone = sanitize_arg(&zone);
    let clean_name = sanitize_arg(&payload.name);
    let clean_type = sanitize_arg(&payload.record_type);
    let clean_data = sanitize_arg(&payload.data);

    let res = run_samba_dns_cmd(
        "delete",
        &format!("'{}' '{}' '{}' '{}'", clean_zone, clean_name, clean_type, clean_data),
        &config,
        payload.dry_run,
    );

    let evt_id = config.audit.record(
        "admin",
        None,
        "DNS_RECORD_DELETE",
        &format!("zone:{}:rec:{}:{}", zone, payload.name, payload.record_type),
        payload.dry_run,
        res.success,
        &format!("Exclusão do registro DNS {} ({})", payload.record_type, payload.name),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] O registro '{}: {}' seria excluído da zona '{}'", payload.record_type, payload.name, zone)
                } else {
                    format!("Registro '{}: {}' excluído com sucesso", payload.record_type, payload.name)
                },
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao excluir registro DNS: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}
