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
use crate::system::{run_cmd_dry, check_service_active, shell_quote, run_ad_operation};
use crate::api::users::{ApiResponse, ActionQuery};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BindStatus {
    pub service_active: bool,
    pub listening_on_5353: bool,
    pub forwarders: Vec<String>,
    pub config_path: String,
    pub recursion: bool,
    pub syntax_valid: bool,
    pub loopback_only: bool,
    pub service_name: String,
    pub warnings: Vec<String>,
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

fn bind_config() -> (&'static str, &'static str, &'static str) {
    if std::path::Path::new("/etc/bind").is_dir() {
        ("/etc/bind/named.conf.options", "/etc/bind/named.conf", "bind9")
    } else { ("/etc/named.conf", "/etc/named.conf", "named") }
}

pub async fn get_bind_status(State(config): State<Arc<AppConfig>>) -> Json<BindStatus> {
    let sudo = config.sudo_password.as_deref();
    let (config_path, main, service) = bind_config();
    let service_active = check_service_active(service, sudo);
    let content = fs::read_to_string(config_path).unwrap_or_default();
    let forwarders = Regex::new(r"forwarders\s*\{([^}]+)\};").unwrap().captures(&content)
        .map(|caps| caps[1].split(';').map(str::trim).filter(|v| !v.is_empty()).map(str::to_string).collect()).unwrap_or_default();
    let listen_res = run_cmd_dry("ss -H -lntu '( sport = :5353 )'", sudo, false);
    let listeners: Vec<_> = listen_res.stdout.lines().filter_map(|line| line.split_whitespace().nth(4)).collect();
    let tcp = listen_res.stdout.lines().any(|line| line.starts_with("tcp") && line.contains("127.0.0.1:5353"));
    let udp = listen_res.stdout.lines().any(|line| line.starts_with("udp") && line.contains("127.0.0.1:5353"));
    let loopback_only = !listeners.is_empty() && listeners.iter().all(|v| *v == "127.0.0.1:5353");
    let syntax_valid = run_cmd_dry(&format!("named-checkconf {}", shell_quote(main)), sudo, false).success;
    let mut warnings = Vec::new();
    if !syntax_valid { warnings.push("Configuração BIND inválida ou named-checkconf indisponível.".into()); }
    if !loopback_only { warnings.push("A porta 5353 deve escutar somente em 127.0.0.1.".into()); }
    if !tcp || !udp { warnings.push("Verifique listeners TCP e UDP na porta 5353.".into()); }
    Json(BindStatus { service_active, listening_on_5353: tcp && udp, forwarders, config_path: config_path.into(),
        recursion: Regex::new(r"recursion\s+yes\s*;").unwrap().is_match(&content), syntax_valid, loopback_only,
        service_name: service.into(), warnings })
}

pub async fn update_forwarders(
    _operator: crate::auth::Administrator,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<UpdateForwardersRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<String>>>) {
    let request = serde_json::json!({"forwarders": payload.forwarders, "dry_run": payload.dry_run});
    let result = run_ad_operation("bind", &request, config.sudo_password.as_deref());
    let id = config.audit.record(&_operator.0.username, None, "BIND_HYBRID_CONFIGURE", "bind:hybrid", payload.dry_run, result.is_ok(), "Configuração BIND recursiva validada com rollback");
    match result {
        Ok(steps) => (StatusCode::OK, Json(ApiResponse { success: true, message: "BIND híbrido: operação concluída.".into(), data: Some(steps), dry_run: payload.dry_run, correlation_id: Some(id) })),
        Err(error) => (StatusCode::BAD_REQUEST, Json(ApiResponse { success: false, message: error, data: None, dry_run: payload.dry_run, correlation_id: Some(id) })),
    }
}

pub async fn test_query(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<TestQueryRequest>,
) -> Json<TestQueryResponse> {
    let sudo = config.sudo_password.as_deref();
    let rtype = payload.record_type.unwrap_or_else(|| "A".to_string()).to_uppercase();
    let domain = payload.domain.trim().to_string();
    if domain.len() > 253 || domain.is_empty() || !domain.chars().all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
        || !["A", "AAAA", "SRV", "SOA", "NS", "MX", "TXT", "CNAME", "PTR"].contains(&rtype.as_str()) {
        return Json(TestQueryResponse { domain, record_type: rtype, results: vec![] });
    }

    let mut targets = vec![
        ("127.0.0.1#53", "Samba Internal DNS (Porta 53)", "127.0.0.1", "53"),
        ("127.0.0.1#5353", "BIND Hybrid Recursive Forwarder (Porta 5353)", "127.0.0.1", "5353"),

    ];

    let content = fs::read_to_string(bind_config().0).unwrap_or_default();
    let upstream: Vec<String> = Regex::new(r"forwarders\s*\{([^}]+)\};").unwrap().captures(&content)
        .map(|caps| caps[1].split(';').filter_map(|f| f.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())).collect()).unwrap_or_default();
    for ip in &upstream { targets.push((ip.as_str(), "Upstream configurado", ip.as_str(), "53")); }
    let mut results = Vec::new();

    for (target_label, desc, ip, port) in targets {
        let start = Instant::now();
        let cmd = format!("dig @{} -p {} {} {} +stats +time=2 +tries=1", ip, port, shell_quote(&domain), shell_quote(&rtype));
        let res = run_cmd_dry(&cmd, sudo, false);
        let elapsed = start.elapsed().as_millis() as u64;

        let mut answers = Vec::new();
        let mut status = "FAILED".to_string();

        if res.success {
            let mut in_answer = false;
            for line in res.stdout.lines() {
                if let Some(captures) = Regex::new(r"status: ([A-Z]+)").unwrap().captures(line) {
                    status = captures[1].to_string();
                }
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
    let service = bind_config().2;
    let cmd = if std::path::Path::new(query_log).exists() {
        format!("tail -n 80 {}", query_log)
    } else {
        format!("journalctl -u {} -n 80 --no-pager", service)
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
    _operator: crate::auth::Administrator,
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

    let (_, main, service) = bind_config();
    let cmd = if action == "stop" { format!("systemctl stop {}", service) } else {
        format!("named-checkconf {} && systemctl {} {}", shell_quote(main), action, service)
    };
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
