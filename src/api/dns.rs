use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, sanitize_arg};
use crate::api::users::ApiResponse;

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
}

#[derive(Deserialize, Debug)]
pub struct AddRecordRequest {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub create_ptr: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct DeleteRecordRequest {
    pub name: String,
    pub record_type: String,
    pub data: String,
}

pub async fn list_zones(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<DnsZone>>> {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let cmd = format!("samba-tool dns zonelist 127.0.0.1 -U administrator --password='{}'", admin_pass);
    let res = run_safe_cmd(&cmd, sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to list DNS zones: {}", res.stderr),
            data: None,
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
        message: format!("Retrieved {} zones", zones.len()),
        data: Some(zones),
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
    let res = run_safe_cmd(&cmd, sudo);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Failed to query records: {}", res.stderr),
            data: None,
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
            if ["A", "AAAA", "PTR", "CNAME", "NS", "SOA", "SRV", "TXT", "MX"].contains(&rtype.as_str()) {
                let mut data = rest.trim().to_string();
                let mut ttl = 900;

                if let Some(idx) = data.find('(') {
                    let meta = data[idx + 1..].trim_end_matches(')').to_string();
                    data = data[..idx].trim().to_string();
                    for meta_part in meta.split(',') {
                        let mp = meta_part.trim();
                        if let Some(t_str) = mp.strip_prefix("ttl=") {
                            ttl = t_str.parse().unwrap_or(900);
                        }
                    }
                }

                records.push(DnsRecord {
                    name: current_name.clone(),
                    record_type: rtype,
                    data,
                    ttl,
                });
            }
        }
    }

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} records for zone '{}'", records.len(), zone),
        data: Some(records),
    })
}

pub async fn create_zone(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateZoneRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let clean_zone = sanitize_arg(payload.zone_name.trim());
    if clean_zone.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Zone name is required".to_string(),
                data: None,
            }),
        );
    }

    let cmd = format!(
        "samba-tool dns zonecreate 127.0.0.1 '{}' -U administrator --password='{}'",
        clean_zone, admin_pass
    );
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: format!("DNS Zone '{}' created successfully", clean_zone),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to create DNS zone: {}", res.stderr),
                data: None,
            }),
        )
    }
}

pub async fn delete_zone(
    Path(zone): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");

    let cmd = format!(
        "samba-tool dns zonedel 127.0.0.1 '{}' -U administrator --password='{}'",
        sanitize_arg(&zone),
        admin_pass
    );
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("DNS Zone '{}' deleted successfully", zone),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to delete DNS zone: {}", res.stderr),
                data: None,
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

    let cmd = format!(
        "samba-tool dns add 127.0.0.1 '{}' '{}' '{}' '{}' -U administrator --password='{}'",
        sanitize_arg(&zone),
        name,
        rtype,
        data,
        admin_pass
    );
    let res = run_safe_cmd(&cmd, sudo);
    if !res.success {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to add DNS record: {}", res.stderr),
                data: None,
            }),
        );
    }

    // Auto PTR Reverse Record Creation
    let mut ptr_msg = String::new();
    if rtype == "A" && payload.create_ptr.unwrap_or(false) {
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
            let check_res = run_safe_cmd(&check_zone_cmd, sudo);
            if !check_res.stdout.contains(&rev_zone) {
                let create_rev_cmd = format!(
                    "samba-tool dns zonecreate 127.0.0.1 '{}' -U administrator --password='{}'",
                    rev_zone, admin_pass
                );
                let _ = run_safe_cmd(&create_rev_cmd, sudo);
            }

            // Add PTR record
            let add_ptr_cmd = format!(
                "samba-tool dns add 127.0.0.1 '{}' '{}' PTR '{}' -U administrator --password='{}'",
                rev_zone, host_ip, fqdn, admin_pass
            );
            let ptr_res = run_safe_cmd(&add_ptr_cmd, sudo);
            if ptr_res.success {
                ptr_msg = format!(" + Reverse PTR record added in {}", rev_zone);
            } else {
                ptr_msg = format!(" (Reverse PTR creation failed: {})", ptr_res.stderr);
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: format!("Record '{}: {} -> {}' created successfully{}", rtype, name, data, ptr_msg),
            data: None,
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
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Record '{}: {}' deleted successfully", payload.record_type, payload.name),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to delete DNS record: {}", res.stderr),
                data: None,
            }),
        )
    }
}
