use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::time::Instant;
use regex::Regex;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, check_service_active, sanitize_arg};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BindStatus {
    pub service_active: bool,
    pub listening_on_5353: bool,
    pub forwarders: Vec<String>,
    pub config_path: String,
    pub recursion: bool,
}

#[derive(Deserialize, Debug)]
pub struct UpdateForwardersRequest {
    pub forwarders: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct TestQueryRequest {
    pub domain: String,
    pub record_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueryBenchmark {
    pub server: String,
    pub description: String,
    pub query_time_ms: u64,
    pub status: String,
    pub answer: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestQueryResponse {
    pub domain: String,
    pub record_type: String,
    pub results: Vec<QueryBenchmark>,
}

pub async fn get_bind_status(State(config): State<Arc<AppConfig>>) -> Json<BindStatus> {
    let sudo = config.sudo_password.as_deref();
    let service_active = check_service_active("named", sudo);

    let listen_res = run_safe_cmd("ss -lntu | grep 5353", sudo);
    let listening_on_5353 = listen_res.stdout.contains("5353");

    let mut forwarders = Vec::new();
    let mut recursion = true;
    let config_path = "/etc/named.conf".to_string();

    if let Ok(content) = fs::read_to_string(&config_path) {
        let re = Regex::new(r"forwarders\s*\{([^}]+)\};").unwrap();
        if let Some(caps) = re.captures(&content) {
            let list_str = &caps[1];
            forwarders = list_str
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if content.contains("recursion no;") {
            recursion = false;
        }
    }

    Json(BindStatus {
        service_active,
        listening_on_5353,
        forwarders,
        config_path,
        recursion,
    })
}

pub async fn update_forwarders(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<UpdateForwardersRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let config_path = "/etc/named.conf";

    let content = match fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    message: format!("Failed to read {}: {}", config_path, e),
                    data: None,
                }),
            );
        }
    };

    let fwd_str = payload
        .forwarders
        .iter()
        .map(|f| format!(" {};", f.trim()))
        .collect::<Vec<_>>()
        .join("");

    let new_block = format!("forwarders {{{} }};", fwd_str);
    let re = Regex::new(r"forwarders\s*\{[^}]*\};").unwrap();
    let new_content = if re.is_match(&content) {
        re.replace(&content, &new_block).to_string()
    } else {
        content.replace("options {", &format!("options {{\n    {}", new_block))
    };

    let temp_path = "/tmp/named.conf.test";
    if let Err(e) = fs::write(temp_path, &new_content) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to write test config: {}", e),
                data: None,
            }),
        );
    }

    let check_cmd = format!("named-checkconf {}", temp_path);
    let check_res = run_safe_cmd(&check_cmd, sudo);
    if !check_res.success {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("named-checkconf validation failed: {}", check_res.stderr),
                data: None,
            }),
        );
    }

    let _ = run_safe_cmd(&format!("cp -f {} {}.bak", config_path, config_path), sudo);
    let write_cmd = format!("cp -f {} {}", temp_path, config_path);
    let write_res = run_safe_cmd(&write_cmd, sudo);
    let _ = fs::remove_file(temp_path);

    if !write_res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to update {}: {}", config_path, write_res.stderr),
                data: None,
            }),
        );
    }

    let _ = run_safe_cmd("systemctl reload named 2>/dev/null || systemctl restart named", sudo);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Updated forwarders and reloaded named.service: {:?}", payload.forwarders),
            data: None,
        }),
    )
}

pub async fn test_query(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<TestQueryRequest>,
) -> Json<TestQueryResponse> {
    let sudo = config.sudo_password.as_deref();
    let rtype = payload.record_type.unwrap_or_else(|| "A".to_string()).to_uppercase();
    let domain = sanitize_arg(payload.domain.trim());

    let targets = vec![
        ("127.0.0.1#53", "Samba Internal DNS (Port 53)", "127.0.0.1", "53"),
        ("127.0.0.1#5353", "BIND Hybrid Recursive Forwarder (Port 5353)", "127.0.0.1", "5353"),
        ("8.8.8.8#53", "Upstream Public DNS (Google 8.8.8.8)", "8.8.8.8", "53"),
    ];

    let mut results = Vec::new();

    for (target_label, desc, ip, port) in targets {
        let start = Instant::now();
        let cmd = format!("dig @{} -p {} '{}' '{}' +stats +time=2", ip, port, domain, rtype);
        let res = run_safe_cmd(&cmd, sudo);
        let elapsed = start.elapsed().as_millis() as u64;

        let mut answers = Vec::new();
        let mut status = "FAILED".to_string();

        if res.success {
            let mut in_answer = false;
            for line in res.stdout.lines() {
                if line.contains("status: NOERROR") {
                    status = "NOERROR".to_string();
                } else if line.contains("status: NXDOMAIN") {
                    status = "NXDOMAIN".to_string();
                } else if line.contains(";; ANSWER SECTION:") {
                    in_answer = true;
                    continue;
                } else if line.starts_with(";;") {
                    in_answer = false;
                }

                if in_answer && !line.trim().is_empty() {
                    answers.push(line.trim().to_string());
                }
            }
        }

        results.push(QueryBenchmark {
            server: target_label.to_string(),
            description: desc.to_string(),
            query_time_ms: elapsed,
            status,
            answer: answers,
        });
    }

    Json(TestQueryResponse {
        domain,
        record_type: rtype,
        results,
    })
}

pub async fn get_bind_logs(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<String>>> {
    let sudo = config.sudo_password.as_deref();
    let query_log = "/var/log/named/query.log";
    let cmd = if std::path::Path::new(query_log).exists() {
        format!("tail -n 80 {}", query_log)
    } else {
        "journalctl -u named -n 80 --no-pager".to_string()
    };

    let res = run_safe_cmd(&cmd, sudo);
    let lines = res.stdout.lines().map(|s| s.to_string()).collect();

    Json(ApiResponse {
        success: true,
        message: "Retrieved BIND logs".to_string(),
        data: Some(lines),
    })
}

pub async fn service_action(
    Path(action): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let valid_actions = ["reload", "restart", "start", "stop"];
    if !valid_actions.contains(&action.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Invalid action '{}'", action),
                data: None,
            }),
        );
    }

    let cmd = format!("systemctl {} named", action);
    let res = run_safe_cmd(&cmd, sudo);
    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("BIND named.service {}ed successfully", action),
                data: None,
            }),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to {} named: {}", action, res.stderr),
                data: None,
            }),
        )
    }
}
