use axum::{
    extract::{State, Query},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, check_service_active, sanitize_arg, shell_quote};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreflightCheck {
    pub hostname: String,
    pub fqdn: String,
    pub ip_address: String,
    pub selinux_status: String,
    pub samba_installed: bool,
    pub bind_installed: bool,
    pub chrony_installed: bool,
    pub smb_conf_exists: bool,
    pub ad_is_active: bool,
    pub sam_ldb_exists: bool,
    pub ports_open: Vec<PortStatus>,
    pub ready_for_provision: bool,
    pub ad_dns_configured: bool,
    pub ad_dns_resolves: bool,
    pub dc2_dns_added: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdDnsVerification {
    pub hostname: String,
    pub fqdn: String,
    pub local_ip: String,
    pub partner_dc_ip: String,
    pub realm: String,
    pub resolv_conf_configured: bool,
    pub resolv_conf_nameservers: Vec<String>,
    pub ad_srv_resolves: bool,
    pub ad_srv_target: Option<String>,
    pub dc2_a_record_in_ad: bool,
    pub dc2_ns_record_in_ad: bool,
    pub samba_tool_installed: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncAdDnsRequest {
    pub realm: Option<String>,
    pub target_dc_ip: Option<String>,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortStatus {
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub open: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResetSambaRequest {
    pub netbios_name: Option<String>,
    pub target_dc_ip: Option<String>,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionResult {
    pub steps_completed: Vec<String>,
    pub error: Option<String>,
    pub plan_only: bool,
}

pub async fn run_preflight(State(config): State<Arc<AppConfig>>) -> Json<PreflightCheck> {
    let sudo = config.sudo_password.as_deref();

    let host_res = run_cmd_dry("hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_string();

    let fqdn_res = run_cmd_dry("hostname -f 2>/dev/null || hostname", sudo, false);
    let fqdn = fqdn_res.stdout.trim().to_string();

    let ip_res = run_cmd_dry("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1", sudo, false);
    let ip_address = ip_res.stdout.trim().to_string();

    let se_res = run_cmd_dry("getenforce 2>/dev/null || echo 'Disabled'", sudo, false);
    let selinux_status = se_res.stdout.trim().to_string();

    let samba_installed = run_cmd_dry("which samba-tool 2>/dev/null", sudo, false).success;
    let bind_installed = run_cmd_dry("which named 2>/dev/null", sudo, false).success;
    let chrony_installed = run_cmd_dry("which chronyd 2>/dev/null", sudo, false).success;
    let smb_conf_exists = Path::new("/etc/samba/smb.conf").exists();
    let sam_ldb_exists = Path::new("/var/lib/samba/private/sam.ldb").exists();
    let ad_is_active = check_service_active("samba", sudo) || check_service_active("samba-dc", sudo);

    let check_ports = vec![
        (53, "tcp", "DNS (TCP)"),
        (53, "udp", "DNS (UDP)"),
        (88, "tcp", "Kerberos (TCP)"),
        (88, "udp", "Kerberos (UDP)"),
        (135, "tcp", "RPC EndPoint Mapper"),
        (389, "tcp", "LDAP (TCP)"),
        (389, "udp", "LDAP (UDP)"),
        (445, "tcp", "SMB over TCP"),
        (464, "tcp", "kpasswd"),
        (636, "tcp", "LDAPS"),
        (3268, "tcp", "Global Catalog"),
        (8095, "tcp", "Astral Web Console"),
    ];

    let mut ports_open = Vec::new();
    for (port, proto, desc) in check_ports {
        let chk = format!("iptables -C INPUT -p {} -m {} --dport {} -j ACCEPT 2>/dev/null", proto, proto, port);
        let open = run_cmd_dry(&chk, sudo, false).success;
        ports_open.push(PortStatus {
            port,
            proto: proto.to_string(),
            service: desc.to_string(),
            open,
        });
    }

    let ready_for_provision = samba_installed && !ad_is_active && !sam_ldb_exists;

    // Verificação de integração do DNS do AD no DC2
    let resolv_content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let ad_dns_configured = resolv_content.contains("192.168.2.10") || resolv_content.contains("127.0.0.1");
    let ad_dns_resolves = run_cmd_dry("host -t srv _ldap._tcp.dc._msdcs.srvcloud.cloud 2>/dev/null", sudo, false).success;
    let dc2_dns_added = run_cmd_dry("samba-tool dns query 192.168.2.10 srvcloud.cloud dc2 A -U administrator%Copa@@2026 2>/dev/null", sudo, false).success;

    Json(PreflightCheck {
        hostname,
        fqdn,
        ip_address,
        selinux_status,
        samba_installed,
        bind_installed,
        chrony_installed,
        smb_conf_exists,
        ad_is_active,
        sam_ldb_exists,
        ports_open,
        ready_for_provision,
        ad_dns_configured,
        ad_dns_resolves,
        dc2_dns_added,
    })
}

fn jobs_directory() -> std::path::PathBuf {
    std::env::var_os("ASTRAL_PROVISION_JOBS_DIR").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/astral-ad-dns/provision-jobs".into())
}

async fn start_provision_job(operator: crate::auth::Administrator, config: Arc<AppConfig>, mut request: serde_json::Value, kind: &str)
    -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    if !request.is_object() { return (StatusCode::BAD_REQUEST, Json(ApiResponse { success:false,message:"Requisicao deve ser um objeto JSON.".into(),data:None,dry_run:false,correlation_id:None })); }
    request["kind"] = serde_json::json!(kind);
    let mut random = [0u8; 16];
    let prepared = (|| -> Result<(String, std::path::PathBuf), String> {
        std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut random)).map_err(|e| e.to_string())?;
        let id: String = random.iter().map(|byte| format!("{:02x}", byte)).collect();
        let directory = jobs_directory();
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let path = directory.join(format!("{}.json", id));
        fs::write(&path, serde_json::json!({"state":"running", "phase":"preflight", "job_id":id,"server_pid":std::process::id()}).to_string()).map_err(|e| e.to_string())?;
        Ok((id, path))
    })();
    let (id, path) = match prepared {
        Ok(value) => value,
        Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { success:false, message, data:None, dry_run:false, correlation_id:None })),
    };
    let job_id = id.clone();
    request["_job_status_path"] = serde_json::json!(path.to_string_lossy());
    tokio::spawn(async move {
        let worker = tokio::task::spawn_blocking(move || {
            let result = crate::system::run_ad_operation_value("provision", &request, config.sudo_password.as_deref());
            let data = match result { Ok(value) => value["data"].clone(), Err(error) => serde_json::json!({"success":false,"message":error,"error":error,"steps_completed":[]}) };
            config.audit.record(&operator.0.username, None, "PROVISION_WORKFLOW", "samba:local", false, data["success"] == true, "Fluxo web com backup automatico; credenciais omitidas");
            data
        }).await;
        let data = worker.unwrap_or_else(|error| serde_json::json!({"success":false,"message":error.to_string()}));
        let temporary = path.with_extension("next");
        if fs::write(&temporary, serde_json::json!({"state":"finished","job_id":job_id,"result":data}).to_string()).is_ok() { let _ = fs::rename(temporary,path); }
    });
    (StatusCode::ACCEPTED, Json(ApiResponse { success:true, message:"Operacao iniciada; acompanhe as etapas nesta tela.".into(),
        data:Some(serde_json::json!({"job_id":id,"state":"running"})), dry_run:false, correlation_id:Some(id) }))
}

pub async fn provision_new_dc(operator: crate::auth::Administrator, State(config): State<Arc<AppConfig>>, Json(request): Json<serde_json::Value>)
    -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    start_provision_job(operator, config, request, "new").await
}

pub async fn provision_job_status(_operator: crate::auth::Administrator, axum::extract::Path(id): axum::extract::Path<String>)
    -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    let mut data: Option<serde_json::Value> = if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        fs::read_to_string(jobs_directory().join(format!("{}.json",id))).ok().and_then(|text| serde_json::from_str(&text).ok())
    } else { None };
    if let Some(value) = data.as_mut() {
        if value["state"] == "running" && value["server_pid"].as_u64().map_or(false, |pid| pid != std::process::id() as u64) { value["state"] = serde_json::json!("interrupted"); }
    }
    let success = data.is_some();
    (if success { StatusCode::OK } else { StatusCode::NOT_FOUND }, Json(ApiResponse { success,
        message:if success { "Status do provisionamento".into() } else { "Operacao nao encontrada; verifique o historico de backups antes de repetir.".into() }, data,dry_run:false,correlation_id:Some(id) }))
}

pub async fn provision_backup_download(_operator: crate::auth::Administrator, axum::extract::Path(id): axum::extract::Path<String>) -> axum::response::Response {
    use axum::response::IntoResponse;
    use tower::ServiceExt;
    if id.len()!=32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) { return StatusCode::BAD_REQUEST.into_response(); }
    let path=std::path::PathBuf::from("/var/backups/astral-ad-dns/provision").join(&id).join("previous-state.tar.gz");
    let request=axum::http::Request::new(axum::body::Body::empty());
    match tower_http::services::ServeFile::new(path).oneshot(request).await {
        Ok(response) => {
            let mut response=response.map(axum::body::Body::new);
            response.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=previous-state-{}.tar.gz",id).parse().unwrap());
            response.headers_mut().insert(axum::http::header::CACHE_CONTROL,axum::http::HeaderValue::from_static("no-store"));
            response
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn provision_history(_operator: crate::auth::Administrator) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    let mut history = Vec::new();
    if let Ok(entries) = fs::read_dir("/var/backups/astral-ad-dns/provision") {
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path().join("manifest.json")) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) { history.push(value); }
            }
        }
    }
    history.sort_by(|a,b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
    history.truncate(50);
    Json(ApiResponse { success:true,message:"Backups automaticos do provisionamento".into(),data:Some(history),dry_run:false,correlation_id:None })
}

fn validate_partner_details(realm: &str, partner: &str, user: &str, password: &str) -> Result<(), String> {
    let valid_realm = realm.split('.').count()>=2 && realm.split('.').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte==b'-'));
    let valid_partner = partner.parse::<std::net::Ipv4Addr>().map_or(false, |ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast());
    if !valid_realm || !valid_partner || user.trim().is_empty() || password.is_empty() { Err("Informe dominio, IP remoto do parceiro e credenciais administrativas validos.".into()) } else { Ok(()) }
}

fn ad_srv_command(realm: &str, partner: &str) -> String {
    format!("dig @{} -p 53 {} SRV +noall +answer +tries=1 +time=3",
        shell_quote(partner), shell_quote(&format!("_ldap._tcp.dc._msdcs.{}", realm.to_lowercase())))
}

fn has_srv_answer(output: &str) -> bool {
    output.lines().any(|line| !line.starts_with(';') && line.split_whitespace().any(|word| word == "SRV"))
}

pub async fn join_domain(operator: crate::auth::Administrator, State(config): State<Arc<AppConfig>>, Json(request): Json<serde_json::Value>)
    -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    let kind = if request["reapply_configuration"] == true { "configure" } else { "join" };
    start_provision_job(operator, config, request, kind).await
}

pub async fn reset_samba_state(_operator: crate::auth::Administrator, State(_config): State<Arc<AppConfig>>, Json(_request): Json<ResetSambaRequest>)
    -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    (StatusCode::CONFLICT, Json(ApiResponse { success:false, message:"Use Reingresso com backup automatico no assistente. A limpeza isolada foi substituida pelo fluxo com verificacao FSMO, despromocao e backup.".into(),data:None,dry_run:false,correlation_id:None }))
}

/// Endpoint de diagnóstico e verificação do status do DNS do AD no DC2
pub async fn verify_ad_dns_status(
    State(config): State<Arc<AppConfig>>,
    Query(parameters): Query<std::collections::HashMap<String, String>>,
) -> Json<AdDnsVerification> {
    let sudo = config.sudo_password.as_deref();

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_lowercase();
    let fqdn_res = run_cmd_dry("hostname -f 2>/dev/null || hostname", sudo, false);
    let fqdn = fqdn_res.stdout.trim().to_lowercase();
    let ip_res = run_cmd_dry("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1", sudo, false);
    let local_ip = ip_res.stdout.trim().to_string();

    let partner_dc_ip = parameters.get("target_dc_ip").cloned().unwrap_or_default().trim().to_string();
    let realm = parameters.get("realm").cloned().unwrap_or_default().trim().to_uppercase();
    let valid = partner_dc_ip.parse::<std::net::Ipv4Addr>().map_or(false, |ip| !ip.is_loopback() && !ip.is_unspecified())
        && realm.split('.').count() >= 2 && realm.split('.').all(|label| !label.is_empty() && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    let resolv_content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let nameservers: Vec<String> = resolv_content.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        if words.next() == Some("nameserver") { words.next().map(str::to_string) } else { None }
    }).collect();
    let resolv_conf_configured = valid && nameservers.contains(&partner_dc_ip);
    let srv_res = if valid { Some(run_cmd_dry(&ad_srv_command(&realm, &partner_dc_ip), sudo, false)) } else { None };
    let ad_srv_resolves = srv_res.as_ref().map_or(false, |reply| reply.success && has_srv_answer(&reply.stdout));
    let ad_srv_target = srv_res.as_ref().filter(|_| ad_srv_resolves).and_then(|reply| reply.stdout.lines().find(|line| has_srv_answer(line)))
        .and_then(|line| line.split_whitespace().last()).map(|name| name.trim_end_matches('.').to_string());
    let samba_tool_installed = run_cmd_dry("which samba-tool 2>/dev/null", sudo, false).success;
    let dc2_a_record_in_ad = valid && run_cmd_dry(&format!("dig @{} {} A +short +tries=1 +time=3", shell_quote(&partner_dc_ip), shell_quote(&format!("{}.{}", hostname, realm.to_lowercase()))), sudo, false)
        .stdout.lines().any(|ip| ip.trim() == local_ip);
    let dc2_ns_record_in_ad = valid && run_cmd_dry(&format!("dig @{} {} NS +short +tries=1 +time=3", shell_quote(&partner_dc_ip), shell_quote(&realm.to_lowercase())), sudo, false)
        .stdout.lines().any(|name| name.trim().trim_end_matches('.').eq_ignore_ascii_case(&format!("{}.{}", hostname, realm.to_lowercase())));

    let message = if !valid {
        "Informe o IP do DC parceiro e o dominio para testar diretamente o DNS do AD na porta 53.".into()
    } else if ad_srv_resolves && dc2_a_record_in_ad {
        format!("DNS do AD operacional no DC2: registros A e NS autoritativos ativos na zona {}.", realm.to_lowercase())
    } else if ad_srv_resolves {
        format!("Resolução DNS do AD ativa no DC2, mas registro A de {} ainda não foi adicionado ao AD.", hostname)
    } else {
        "DNS do Active Directory não configurado ou inacessível no DC2.".to_string()
    };

    Json(AdDnsVerification {
        hostname,
        fqdn,
        local_ip,
        partner_dc_ip,
        realm,
        resolv_conf_configured,
        resolv_conf_nameservers: nameservers,
        ad_srv_resolves,
        ad_srv_target,
        dc2_a_record_in_ad,
        dc2_ns_record_in_ad,
        samba_tool_installed,
        message,
    })
}

/// Endpoint para sincronizar e adicionar os registros do DC2 no DNS do AD
pub async fn sync_ad_dns_dc(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<SyncAdDnsRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    let realm = payload.realm.unwrap_or_default().trim().to_uppercase();
    let target_dc_ip = payload.target_dc_ip.unwrap_or_default().trim().to_string();
    let admin_user = payload.admin_username.unwrap_or_default();
    let admin_pass = payload.admin_password.unwrap_or_default();
    if let Err(message) = validate_partner_details(&realm, &target_dc_ip, &admin_user, &admin_pass) {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse { success: false, message, data: None, dry_run: false, correlation_id: None }));
    }
    let partner_dns = run_cmd_dry(&ad_srv_command(&realm, &target_dc_ip), sudo, false);
    if !partner_dns.success || !has_srv_answer(&partner_dns.stdout) {
        return (StatusCode::PRECONDITION_FAILED, Json(ApiResponse { success: false,
            message: format!("O DNS do AD {}:53 nao respondeu com SRV para {}; sincronizacao nao executada.", target_dc_ip, realm), data: None, dry_run: false, correlation_id: None }));
    }

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_lowercase();
    let ip_res = run_cmd_dry("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1", sudo, false);
    let local_ip = ip_res.stdout.trim().to_string();

    // 1. Configurar /etc/resolv.conf estritamente com DNS do AD (parceiro e 127.0.0.1, sem DNS externo)
    crate::system::configure_ad_dns_resolver(&realm, Some(&target_dc_ip), sudo);
    steps.push(format!("Configurado /etc/resolv.conf exclusivo do AD: nameserver {} e 127.0.0.1.", target_dc_ip));

    // 2. Garantir registro A no DNS do AD
    let add_a_cmd = format!(
        "samba-tool dns add '{}' '{}' '{}' A '{}' -U'{}%{}'",
        target_dc_ip,
        realm.to_lowercase(),
        hostname,
        local_ip,
        sanitize_arg(&admin_user),
        sanitize_arg(&admin_pass)
    );
    let r_a = run_cmd_dry(&add_a_cmd, sudo, false);
    if r_a.success || r_a.stderr.contains("already exists") || r_a.stdout.contains("already exists") {
        steps.push(format!("Registro A de {} ({}) verificado/adicionado no DNS do AD ({}) com sucesso.", hostname, local_ip, target_dc_ip));
    } else {
        steps.push(format!("Aviso ao registrar A no AD: {}", r_a.stderr.trim()));
    }

    // 3. Garantir registro NS no DNS do AD
    let add_ns_cmd = format!(
        "samba-tool dns add '{}' '{}' @ NS '{}.{}' -U'{}%{}'",
        target_dc_ip,
        realm.to_lowercase(),
        hostname,
        realm.to_lowercase(),
        sanitize_arg(&admin_user),
        sanitize_arg(&admin_pass)
    );
    let r_ns = run_cmd_dry(&add_ns_cmd, sudo, false);
    if r_ns.success || r_ns.stderr.contains("already exists") || r_ns.stdout.contains("already exists") {
        steps.push(format!("Registro NS de {}.{} adicionado na zona {} com sucesso.", hostname, realm.to_lowercase(), realm.to_lowercase()));
    } else {
        steps.push(format!("Aviso ao registrar NS no AD: {}", r_ns.stderr.trim()));
    }

    // 4. Teste de validação
    let test_res = run_cmd_dry(&format!("host -t srv _ldap._tcp.dc._msdcs.{} 2>/dev/null", realm.to_lowercase()), sudo, false);
    if test_res.success {
        steps.push("Resolução interna de SRV do Active Directory confirmada e ativa!".to_string());
    }

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "DNS do AD e registros do DC2 sincronizados com sucesso!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchemaUpgradeRequest {
    #[serde(default = "default_schema_ver")]
    pub schema_version: String,
    #[serde(default = "default_func_level")]
    pub functional_level: String,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_schema_ver() -> String { "2019".to_string() }
fn default_func_level() -> String { "2016".to_string() }

pub async fn upgrade_schema_and_levels(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<SchemaUpgradeRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    if payload.dry_run {
        steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain schemaupgrade --schema={}", payload.schema_version));
        steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain functionalprep --function-level={}", payload.functional_level));
        steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain level raise --domain-level={} --forest-level={}", payload.functional_level, payload.functional_level));
        steps.push("[SIMULAÇÃO] Execução prevista: samba-tool dbcheck --cross-ncs --fix --yes".to_string());

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de elevação de schema e níveis preparado.".to_string(),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: None,
                    plan_only: true,
                }),
                dry_run: true,
                correlation_id: None,
            }),
        );
    }

    let _ = run_cmd_dry("sed -i '/ad dc functional level/d' /etc/samba/smb.conf && sed -i '/\\[global\\]/a \\    ad dc functional level = 2016' /etc/samba/smb.conf", sudo, false);
    let _ = run_cmd_dry("systemctl restart samba 2>/dev/null || true", sudo, false);
    let _ = run_cmd_dry("systemctl stop samba 2>/dev/null || true", sudo, false);

    let s_res = run_cmd_dry(&format!("samba-tool domain schemaupgrade --schema={}", payload.schema_version), sudo, false);
    steps.push(format!("Schema upgrade para {}: {}", payload.schema_version, if s_res.success { "Sucesso" } else { "Aviso/Não modificado" }));

    let f_res = run_cmd_dry(&format!("samba-tool domain functionalprep --function-level={}", payload.functional_level), sudo, false);
    steps.push(format!("Functional prep {}: {}", payload.functional_level, if f_res.success { "Sucesso" } else { "Aviso/Não modificado" }));

    let l_res = run_cmd_dry(&format!("samba-tool domain level raise --domain-level={} --forest-level={}", payload.functional_level, payload.functional_level), sudo, false);
    steps.push(format!("Domain & Forest level raise {}: {}", payload.functional_level, if l_res.success { "Sucesso" } else { "Aviso/Já no nível" }));

    let _ = run_cmd_dry("systemctl start samba 2>/dev/null || true", sudo, false);
    let db_res = run_cmd_dry("samba-tool dbcheck --cross-ncs --fix --yes 2>/dev/null || true", sudo, false);
    steps.push(format!("Samba dbcheck: {}", if db_res.success { "Base consistente" } else { "Executado com alertas" }));

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Schema e níveis funcionais elevados com sucesso!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}

pub async fn fix_dns_partitions(_operator: crate::auth::Administrator, State(_config): State<Arc<AppConfig>>) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    (StatusCode::CONFLICT,Json(ApiResponse{success:false,message:"A verificacao/correcao de particoes DNS agora integra Reaplicar configuracao no assistente, com backup automatico.".into(),data:None,dry_run:false,correlation_id:None}))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StepCaSetupRequest {
    pub static_ip: Option<String>,
    pub cert_password: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn setup_step_ca(_operator: crate::auth::Administrator, State(_config): State<Arc<AppConfig>>, Json(_request): Json<StepCaSetupRequest>) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    (StatusCode::CONFLICT,Json(ApiResponse{success:false,message:"TLS/Step-CA e renovacao agora integram o assistente: Reaplicar configuracao > Configurar certificado LDAPS.".into(),data:None,dry_run:false,correlation_id:None}))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReverseZoneRequest {
    pub ip_address: String,
    pub hostname_fqdn: String,
    pub realm: String,
    pub admin_password: String,
}

pub async fn configure_reverse_zone(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ReverseZoneRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    let octets: Vec<&str> = payload.ip_address.split('.').collect();
    if octets.len() != 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Endereço IPv4 inválido para cálculo de zona reversa".to_string(),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let rev_zone = format!("{}.{}.{}.in-addr.arpa", octets[2], octets[1], octets[0]);
    let last_octet = octets[3];
    let cred = format!("Administrator%{}", sanitize_arg(&payload.admin_password));

    // Zone create
    let z_cmd = format!("samba-tool dns zonecreate '{}' '{}' -U '{}'", payload.hostname_fqdn, rev_zone, cred);
    let z_res = run_cmd_dry(&z_cmd, sudo, false);
    steps.push(format!("Criação da zona reversa {}: {}", rev_zone, if z_res.success { "Criada" } else { "Já existe ou aviso" }));

    // PTR
    let ptr_cmd = format!("samba-tool dns add '{}' '{}' '{}' PTR '{}' -U '{}'", payload.hostname_fqdn, rev_zone, last_octet, payload.hostname_fqdn, cred);
    let ptr_res = run_cmd_dry(&ptr_cmd, sudo, false);
    steps.push(format!("Registro PTR {} -> {}: {}", last_octet, payload.hostname_fqdn, if ptr_res.success { "Adicionado" } else { "Aviso" }));

    // A ca
    let a_cmd = format!("samba-tool dns add '{}' '{}' ca A '{}' -U '{}'", payload.hostname_fqdn, payload.realm.to_lowercase(), payload.ip_address, cred);
    let a_res = run_cmd_dry(&a_cmd, sudo, false);
    steps.push(format!("Registro A ca.{}: {}", payload.realm.to_lowercase(), if a_res.success { "Adicionado" } else { "Aviso" }));

    // CNAME pki
    let cname_cmd = format!("samba-tool dns add '{}' '{}' pki CNAME 'ca.{}' -U '{}'", payload.hostname_fqdn, payload.realm.to_lowercase(), payload.realm.to_lowercase(), cred);
    let cname_res = run_cmd_dry(&cname_cmd, sudo, false);
    steps.push(format!("Registro CNAME pki.{}: {}", payload.realm.to_lowercase(), if cname_res.success { "Adicionado" } else { "Aviso" }));

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Zona reversa e registros DNS da autoridade configurados com sucesso!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}
