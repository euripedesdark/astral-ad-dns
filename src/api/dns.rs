use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

pub async fn list_zones(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<DnsZone>>> {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let cmd = format!("samba-tool dns zonelist 127.0.0.1 -U administrator --password='{}'", admin_pass);
    let res = run_cmd_dry(&cmd, sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar zonas DNS: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let mut zones = Vec::new();
    let mut current_name = String::new();
    let mut current_type = "DNS_ZONE_TYPE_PRIMARY".to_string();
    let mut current_dp = String::new();

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
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let cmd = format!(
        "samba-tool dns query 127.0.0.1 '{}' @ ALL -U administrator --password='{}'",
        sanitize_arg(&zone),
        admin_pass
    );
    let res = run_cmd_dry(&cmd, sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao consultar registros DNS: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let mut records = Vec::new();
    let mut current_name = "@".to_string();

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

    Json(ApiResponse {
        success: true,
        message: format!("Recuperados {} registros na zona '{}'", records.len(), zone),
        data: Some(records),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_zone(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateZoneRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

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

    let cmd = format!(
        "samba-tool dns zonecreate 127.0.0.1 '{}' -U administrator --password='{}'",
        zone, admin_pass
    );
    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);

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
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

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

    let cmd = format!(
        "samba-tool dns zonedel 127.0.0.1 '{}' -U administrator --password='{}'",
        sanitize_arg(&zone),
        admin_pass
    );
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

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
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

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

    let cmd = format!(
        "samba-tool dns add 127.0.0.1 '{}' '{}' '{}' '{}' -U administrator --password='{}'",
        sanitize_arg(&zone),
        name,
        rtype,
        data,
        admin_pass
    );
    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);

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
            let check_zone_cmd = format!("samba-tool dns zonelist 127.0.0.1 -U administrator --password='{}'", admin_pass);
            let check_res = run_cmd_dry(&check_zone_cmd, sudo, false);
            if !check_res.stdout.contains(&rev_zone) {
                let create_rev_cmd = format!(
                    "samba-tool dns zonecreate 127.0.0.1 '{}' -U administrator --password='{}'",
                    rev_zone, admin_pass
                );
                let _ = run_cmd_dry(&create_rev_cmd, sudo, false);
            }

            // Add PTR record
            let add_ptr_cmd = format!(
                "samba-tool dns add 127.0.0.1 '{}' '{}' PTR '{}' -U administrator --password='{}'",
                rev_zone, host_ip, fqdn, admin_pass
            );
            let ptr_res = run_cmd_dry(&add_ptr_cmd, sudo, false);
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
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let cmd = format!(
        "samba-tool dns delete 127.0.0.1 '{}' '{}' '{}' '{}' -U administrator --password='{}'",
        sanitize_arg(&zone),
        sanitize_arg(&payload.name),
        sanitize_arg(&payload.record_type),
        sanitize_arg(&payload.data),
        admin_pass
    );
    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);

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
