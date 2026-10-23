use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::time::Instant;
use regex::Regex;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, check_service_active, sanitize_arg};
use crate::api::users::{ApiResponse, ActionQuery};

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
    #[serde(default)]
    pub dry_run: bool,
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

    let listen_res = run_cmd_dry("ss -lntu | grep 5353", sudo, false);
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

    // Pré-validação de cada endereço IP
    for fwd in &payload.forwarders {
        let f = fwd.trim();
        if !f.is_empty() && f.parse::<std::net::Ipv4Addr>().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    message: format!("Endereço IP de forwarder inválido: '{}'", f),
                    data: None,
                    dry_run: payload.dry_run,
                    correlation_id: None,
                }),
            );
        }
    }

    let content = match fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    message: format!("Falha ao ler {}: {}", config_path, e),
                    data: None,
                    dry_run: payload.dry_run,
                    correlation_id: None,
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
                message: format!("Falha ao escrever configuração de teste: {}", e),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let check_cmd = format!("named-checkconf {}", temp_path);
    let check_res = run_cmd_dry(&check_cmd, sudo, false);
    if !check_res.success {
        let _ = fs::remove_file(temp_path);
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Validação com named-checkconf falhou: {}", check_res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    if payload.dry_run {
        let _ = fs::remove_file(temp_path);
        let evt_id = config.audit.record(
            "admin",
            None,
            "BIND_FORWARDERS_UPDATE",
            "named:forwarders",
            true,
            true,
            &format!("[SIMULAÇÃO] named-checkconf aprovado para forwarders: {:?}", payload.forwarders),
        );
        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("[SIMULAÇÃO] Sintaxe validada pelo named-checkconf. O novo bloco seria aplicado: {}", new_block),
                data: None,
                dry_run: true,
                correlation_id: Some(evt_id),
            }),
        );
    }

    let _ = run_cmd_dry(&format!("cp -f {} {}.bak", config_path, config_path), sudo, false);
    let write_cmd = format!("cp -f {} {}", temp_path, config_path);
    let write_res = run_cmd_dry(&write_cmd, sudo, false);
    let _ = fs::remove_file(temp_path);

    if !write_res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao gravar {}: {}", config_path, write_res.stderr),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let _ = run_cmd_dry("systemctl reload named 2>/dev/null || systemctl restart named", sudo, false);

    let evt_id = config.audit.record(
        "admin",
        None,
        "BIND_FORWARDERS_UPDATE",
        "named:forwarders",
        false,
        true,
        &format!("Forwarders do BIND 9 atualizados: {:?}", payload.forwarders),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Forwarders atualizados e named.service recarregado com sucesso: {:?}", payload.forwarders),
            data: None,
            dry_run: false,
            correlation_id: Some(evt_id),
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
        ("127.0.0.1#53", "Samba Internal DNS (Porta 53)", "127.0.0.1", "53"),
        ("127.0.0.1#5353", "BIND Hybrid Recursive Forwarder (Porta 5353)", "127.0.0.1", "5353"),
        ("8.8.8.8#53", "Upstream Public DNS (Google 8.8.8.8)", "8.8.8.8", "53"),
    ];

    let mut results = Vec::new();

    for (target_label, desc, ip, port) in targets {
        let start = Instant::now();
        let cmd = format!("dig @{} -p {} '{}' '{}' +stats +time=2", ip, port, domain, rtype);
        let res = run_cmd_dry(&cmd, sudo, false);
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

    let res = run_cmd_dry(&cmd, sudo, false);
    let lines = res.stdout.lines().map(|s| s.to_string()).collect();

    Json(ApiResponse {
        success: true,
        message: "Logs do BIND 9 recuperados".to_string(),
        data: Some(lines),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn service_action(
    Path(action): Path<String>,
    Query(q): Query<ActionQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    let valid_actions = ["reload", "restart", "start", "stop"];
    if !valid_actions.contains(&action.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("Ação inválida: '{}'", action),
                data: None,
                dry_run: q.dry_run,
                correlation_id: None,
            }),
        );
    }

    let cmd = format!("systemctl {} named", action);
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        &format!("SERVICE_{}", action.to_uppercase()),
        "service:named",
        q.dry_run,
        res.success,
        &format!("Comando systemctl {} named", action),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o serviço named receberia 'systemctl {}'", action)
                } else {
                    format!("Serviço BIND 9 (named) '{}' executado com sucesso", action)
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
                message: format!("Falha na ação '{}' do named: {}", action, res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}
