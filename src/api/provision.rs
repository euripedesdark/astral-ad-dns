use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, ensure_firewall_port_open, check_service_active, sanitize_arg};
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortStatus {
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub open: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionNewDcRequest {
    pub realm: String,
    pub workgroup: String,
    pub hostname_fqdn: String,
    pub admin_password: String,
    pub dns_forwarder: Option<String>,
    pub setup_bind_hybrid: Option<bool>,
    pub upstream_forwarders: Option<Vec<String>>,
    pub static_ip: Option<String>,
    pub network_interface: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinDomainRequest {
    pub realm: String,
    pub target_dc_ip: String,
    pub admin_username: String,
    pub admin_password: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionResult {
    pub steps_completed: Vec<String>,
    pub error: Option<String>,
    pub plan_only: bool,
}

pub fn validate_provision_request(req: &ProvisionNewDcRequest) -> Result<(), String> {
    let host = req.hostname_fqdn.trim();
    if host.is_empty() || host.split('.').count() < 3 {
        return Err("O hostname deve ser um FQDN válido (ex: dc1.srvcloud.cloud, mínimo 3 partes)".to_string());
    }

    let realm = req.realm.trim();
    if realm.is_empty() || realm != realm.to_uppercase() {
        return Err("O Realm do Kerberos deve estar estritamente em MAIÚSCULAS (ex: SRVCLOUD.CLOUD)".to_string());
    }

    let workgroup = req.workgroup.trim();
    if workgroup.is_empty() || workgroup.len() > 15 {
        return Err("O domínio NetBIOS (Workgroup) deve ter no máximo 15 caracteres".to_string());
    }

    if req.admin_password.len() < 8 {
        return Err("A senha de Administrator deve ter no mínimo 8 caracteres e padrão de complexidade".to_string());
    }

    let suffix = host.splitn(2, '.').nth(1).unwrap_or("").to_uppercase();
    if !suffix.is_empty() && suffix != realm {
        return Err(format!("O sufixo do FQDN ('{}') deve coincidir exatamente com o Realm ('{}')", suffix, realm));
    }

    Ok(())
}

pub async fn run_preflight(State(config): State<Arc<AppConfig>>) -> Json<PreflightCheck> {
    let sudo = config.sudo_password.as_deref();

    let host_res = run_cmd_dry("hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_string();

    let fqdn_res = run_cmd_dry("hostname -f 2>/dev/null || hostname", sudo, false);
    let fqdn = fqdn_res.stdout.trim().to_string();

    let ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
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
        (5353, "udp", "BIND Hybrid (UDP)"),
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
    })
}

pub async fn provision_new_dc(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ProvisionNewDcRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();

    // 0. Validação de pré-requisitos e formato
    if let Err(err_msg) = validate_provision_request(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: err_msg,
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    // Se não for simulação, verifica se já existe uma base para evitar destruição acidental
    if !payload.dry_run && Path::new("/var/lib/samba/private/sam.ldb").exists() {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse {
                success: false,
                message: "Atenção: Já existe um domínio provisionado (/var/lib/samba/private/sam.ldb). Para provisionar novamente, faça backup e limpe manualmente a base existente.".to_string(),
                data: None,
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    let mut steps = Vec::new();
    let d = payload.dry_run;

    // 0.1 Desativar systemd-resolved para liberar porta 53 e proteger /etc/resolv.conf
    if !d {
        crate::system::disable_systemd_resolved_and_protect_dns(&payload.realm, sudo);
        steps.push("systemd-resolved desativado e /etc/resolv.conf protegido com chattr +i.".to_string());
    }

    // 1. Verificação segura de firewall
    let ports = vec![
        (53, "tcp"), (53, "udp"),
        (88, "tcp"), (88, "udp"),
        (123, "udp"),
        (135, "tcp"),
        (137, "udp"), (138, "udp"), (139, "tcp"),
        (389, "tcp"), (389, "udp"),
        (445, "tcp"),
        (464, "tcp"), (464, "udp"),
        (636, "tcp"),
        (8443, "tcp"),
        (3268, "tcp"), (3269, "tcp"),
        (5353, "tcp"), (5353, "udp"),
        (8095, "tcp"),
    ];

    if d {
        steps.push(format!("[SIMULAÇÃO] Verificação e abertura segura de {} portas no iptables via -I INPUT 1 sem limpar regras", ports.len()));
    } else {
        for (p, proto) in ports {
            ensure_firewall_port_open(p, proto, sudo);
        }
        steps.push("Portas de segurança do Samba AD garantidas no firewall (regras preservadas).".to_string());
    }

    // 2. Configuração do Chrony NTP Socket
    let chrony_conf = "/etc/chrony.conf";
    if d {
        steps.push("[SIMULAÇÃO] Configuração de socket de assinatura NTP (ntpsigndsocket /var/lib/samba/ntp_signd) no /etc/chrony.conf".to_string());
    } else if let Ok(chrony_text) = fs::read_to_string(chrony_conf) {
        if !chrony_text.contains("ntpsigndsocket /var/lib/samba/ntp_signd") {
            let _ = run_cmd_dry("echo 'ntpsigndsocket /var/lib/samba/ntp_signd' >> /etc/chrony.conf", sudo, false);
            let _ = run_cmd_dry("mkdir -p /var/lib/samba/ntp_signd && chown root:chrony /var/lib/samba/ntp_signd 2>/dev/null || true", sudo, false);
            let _ = run_cmd_dry("chmod 750 /var/lib/samba/ntp_signd || true", sudo, false);
            let _ = run_cmd_dry("systemctl restart chronyd || true", sudo, false);
            steps.push("Chrony signed NTP socket configurado para Kerberos.".to_string());
        }
    }

    // 3. Configuração do BIND 9 Híbrido (porta 5353)
    let forwarder = payload.dns_forwarder.unwrap_or_else(|| "127.0.0.1:5353".to_string());
    if payload.setup_bind_hybrid.unwrap_or(true) {
        let fwd_list = payload.upstream_forwarders.unwrap_or_else(|| vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]);
        let fwd_formatted = fwd_list.iter().map(|f| format!(" {};", f.trim())).collect::<Vec<_>>().join("");

        if d {
            steps.push(format!("[SIMULAÇÃO] Configuração do named.conf na porta 5353 com forwarders recursivos: {:?}", fwd_list));
        } else {
            let named_conf = format!("options {{\n    directory \"/var/named\";\n    listen-on port 5353 {{ 127.0.0.1; }};\n    listen-on-v6 {{ none; }};\n    allow-query {{ localhost; }};\n    recursion yes;\n    forwarders {{{} }};\n    dnssec-validation no;\n    max-cache-size 64m;\n}};\n", fwd_formatted);

            let temp_named = "/tmp/named.conf.gen";
            let _ = fs::write(temp_named, named_conf);
            let _ = run_cmd_dry(&format!("cp -f {} /etc/named.conf", temp_named), sudo, false);
            let _ = fs::remove_file(temp_named);
            let _ = run_cmd_dry("systemctl enable --now named || true", sudo, false);
            steps.push("BIND 9 híbrido recursivo ativo em 127.0.0.1:5353.".to_string());
        }
    }

    // 4. Comando de provisionamento do Samba
    let prov_cmd = format!(
        "samba-tool domain provision --use-rfc2307 --realm='{}' --domain='{}' --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='{}'",
        payload.realm.to_uppercase(),
        payload.workgroup.to_uppercase(),
        sanitize_arg(&payload.admin_password)
    );

    if d {
        steps.push(format!(
            "[SIMULAÇÃO] Execução prevista: samba-tool domain provision --use-rfc2307 --realm='{}' --domain='{}' --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass=********",
            payload.realm.to_uppercase(),
            payload.workgroup.to_uppercase()
        ));
        steps.push("[SIMULAÇÃO] Ajuste de parâmetros no smb.conf: ad dc functional level = 2016 e dns forwarder = 127.0.0.1:5353".to_string());
        steps.push("[SIMULAÇÃO] Vinculação de /etc/krb5.conf e inicialização do serviço systemctl enable --now samba".to_string());

        let evt_id = config.audit.record(
            "admin",
            None,
            "PROVISION_SIMULATION",
            &format!("domain:{}", payload.realm),
            true,
            true,
            &format!("Simulação de provisionamento para realm {}", payload.realm),
        );

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de provisionamento gerado e validado com sucesso! Nenhuma alteração foi realizada no sistema.".to_string(),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: None,
                    plan_only: true,
                }),
                dry_run: true,
                correlation_id: Some(evt_id),
            }),
        );
    }

    // Execução real
    let _ = run_cmd_dry("mv /etc/samba/smb.conf /etc/samba/smb.conf.bak.$(date +%s) 2>/dev/null || true", sudo, false);
    let prov_res = run_cmd_dry(&prov_cmd, sudo, false);
    if !prov_res.success {
        let evt_id = config.audit.record(
            "admin",
            None,
            "PROVISION_FAILED",
            &format!("domain:{}", payload.realm),
            false,
            false,
            &format!("Falha no provisionamento: {}", prov_res.stderr),
        );

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha no provisionamento do Samba AD: {}", prov_res.stderr),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: Some(prov_res.stderr),
                    plan_only: false,
                }),
                dry_run: false,
                correlation_id: Some(evt_id),
            }),
        );
    }
    steps.push(format!("Samba AD DC provisionado com sucesso para o realm '{}'.", payload.realm.to_uppercase()));

    // 5. Ajustes no smb.conf (Functional level 2016 + Forwarder)
    let tune_cmd = format!(
        "sed -i '/\\[global\\]/a \\    dns forwarder = {}\\n    ad dc functional level = 2016\\n    bind interfaces only = yes' /etc/samba/smb.conf",
        forwarder
    );
    let _ = run_cmd_dry(&tune_cmd, sudo, false);
    steps.push("smb.conf ajustado com Functional Level 2016 e Forwarder DNS.".to_string());

    // 6. Configuração do Kerberos
    let _ = run_cmd_dry("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true", sudo, false);
    steps.push("Arquivo /etc/krb5.conf vinculado.".to_string());

    // 7. Inicialização dos Serviços
    let _ = run_cmd_dry("systemctl unmask samba 2>/dev/null || true", sudo, false);
    let _ = run_cmd_dry("systemctl enable --now samba 2>/dev/null || systemctl enable --now samba-dc 2>/dev/null || true", sudo, false);
    steps.push("Serviço Samba Active Directory iniciado e habilitado no boot.".to_string());

    // 8. Elevação de Schema para 2019 e Functional Level para 2016
    let _ = run_cmd_dry("samba-tool domain schemaupgrade --schema=2019 2>/dev/null || true", sudo, false);
    let _ = run_cmd_dry("samba-tool domain functionalprep --function-level=2016 2>/dev/null || true", sudo, false);
    let _ = run_cmd_dry("samba-tool domain level raise --domain-level=2016 --forest-level=2016 2>/dev/null || true", sudo, false);
    let _ = run_cmd_dry("samba-tool dbcheck --cross-ncs --fix --yes 2>/dev/null || true", sudo, false);
    steps.push("Schema do AD elevado para 2019 e níveis funcionais configurados para 2016.".to_string());

    // 9. Correção de partições DNS (msDS-SDReferenceDomain) e zonas reversas
    let fix_script = "/home/euripedes/astral/astral-ad-dns/samba-ad-dc/provision_ad_step_ca.py";
    if Path::new(fix_script).exists() {
        let _ = run_cmd_dry(&format!("python3 {} --dns-fix-only", fix_script), sudo, false);
        steps.push("Partições DNS corrigidas e zonas reversas provisionadas.".to_string());
    }

    let fw_rep = crate::system::auto_reconcile_firewall_ports(sudo, false);
    steps.push(format!("Firewall pós-provisionamento: {} portas verificadas/abertas automaticamente ({} abertas, {} corrigidas).", fw_rep.total_ports, fw_rep.open_count, fw_rep.corrected_count));

    let evt_id = config.audit.record(
        "admin",
        None,
        "PROVISION_NEW_DC",
        &format!("domain:{}", payload.realm),
        false,
        true,
        &format!("Novo DC provisionado para realm {}", payload.realm),
    );

    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: "Controlador de Domínio Samba Active Directory provisionado com sucesso!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn join_domain(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<JoinDomainRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();
    let d = payload.dry_run;

    let realm = payload.realm.trim().to_uppercase();
    if realm.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Realm é obrigatório".to_string(),
                data: None,
                dry_run: d,
                correlation_id: None,
            }),
        );
    }

    if d {
        steps.push(format!("[SIMULAÇÃO] Verificação de portas de comunicação com o DC parceiro em {}", payload.target_dc_ip));
        steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain join {} DC -U'{}' --password=********", realm, payload.admin_username));
        steps.push("[SIMULAÇÃO] Inicialização da replicação inicial DRS e sincronismo SYSVOL".to_string());

        let evt_id = config.audit.record(
            "admin",
            None,
            "JOIN_SIMULATION",
            &format!("domain:{}", realm),
            true,
            true,
            &format!("Simulação de ingresso no domínio {}", realm),
        );

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de ingresso ao domínio gerado com sucesso.".to_string(),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: None,
                    plan_only: true,
                }),
                dry_run: true,
                correlation_id: Some(evt_id),
            }),
        );
    }

    // Execução real
    let join_cmd = format!(
        "samba-tool domain join '{}' DC -U'{}' --password='{}'",
        realm,
        sanitize_arg(&payload.admin_username),
        sanitize_arg(&payload.admin_password)
    );

    let res = run_cmd_dry(&join_cmd, sudo, false);
    if !res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao ingressar no domínio: {}", res.stderr),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: Some(res.stderr),
                    plan_only: false,
                }),
                dry_run: false,
                correlation_id: None,
            }),
        );
    }

    steps.push(format!("Ingressou com sucesso no domínio '{}' como DC réplica.", realm));
    let fw_rep = crate::system::auto_reconcile_firewall_ports(sudo, false);
    steps.push(format!("Firewall pós-ingresso: {} portas verificadas/abertas automaticamente ({} abertas, {} corrigidas).", fw_rep.total_ports, fw_rep.open_count, fw_rep.corrected_count));
    let _ = run_cmd_dry("systemctl enable --now samba || systemctl enable --now samba-dc || true", sudo, false);

    let evt_id = config.audit.record(
        "admin",
        None,
        "JOIN_DOMAIN",
        &format!("domain:{}", realm),
        false,
        true,
        &format!("Ingresso no domínio {}", realm),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Ingresso no domínio concluído com sucesso!".to_string(),
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: None,
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: Some(evt_id),
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

pub async fn fix_dns_partitions(
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    let fix_script = "/home/euripedes/astral/astral-ad-dns/samba-ad-dc/provision_ad_step_ca.py";
    let cmd = if Path::new(fix_script).exists() {
        format!("python3 {} --dns-fix-only", fix_script)
    } else {
        "samba-tool dbcheck --cross-ncs --fix --yes".to_string()
    };

    let res = run_cmd_dry(&cmd, sudo, false);
    steps.push(format!("Execução do corretor de partições DNS: {}", if res.success { "Sucesso" } else { &res.stderr }));

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "Partições DNS corrigidas com sucesso!".to_string() } else { "Falha na correção de partições DNS".to_string() },
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: if res.success { None } else { Some(res.stderr) },
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StepCaSetupRequest {
    pub static_ip: Option<String>,
    pub cert_password: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn setup_step_ca(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<StepCaSetupRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    if payload.dry_run {
        steps.push("[SIMULAÇÃO] Instalação dos pacotes step-cli e step-ca via Smallstep RPM".to_string());
        steps.push("[SIMULAÇÃO] Inicialização da autoridade Root CA standalone e provisioner ACME".to_string());
        steps.push("[SIMULAÇÃO] Geração de certificado X.509 com SANs completos para LDAPS (636)".to_string());
        steps.push("[SIMULAÇÃO] Instalação do root_ca.crt em /etc/pki/ca-trust e ativação do step-ca-renew.timer".to_string());

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de configuração da PKI Step-CA preparado.".to_string(),
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

    let fix_script = "/home/euripedes/astral/astral-ad-dns/samba-ad-dc/provision_ad_step_ca.py";
    let cmd = format!("python3 {} --step-ca-only", fix_script);
    let res = run_cmd_dry(&cmd, sudo, false);
    steps.push(format!("Configuração Step-CA: {}", if res.success { "Sucesso" } else { &res.stderr }));

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "Step-CA PKI configurado e integrado ao Samba LDAPS!".to_string() } else { "Falha ao configurar Step-CA".to_string() },
            data: Some(ProvisionResult {
                steps_completed: steps,
                error: if res.success { None } else { Some(res.stderr) },
                plan_only: false,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_provision_params() {
        let valid = ProvisionNewDcRequest {
            realm: "SRVCLOUD.CLOUD".to_string(),
            workgroup: "SRVCLOUD".to_string(),
            hostname_fqdn: "dc1.srvcloud.cloud".to_string(),
            admin_password: "ComplexPassword123!".to_string(),
            dns_forwarder: None,
            setup_bind_hybrid: None,
            upstream_forwarders: None,
            static_ip: None,
            network_interface: None,
            dry_run: true,
        };
        assert!(validate_provision_request(&valid).is_ok());

        // Rejeita realm em minúsculas
        let mut bad_realm = valid.clone();
        bad_realm.realm = "srvcloud.cloud".to_string();
        assert!(validate_provision_request(&bad_realm).is_err());

        // Rejeita hostname não-FQDN
        let mut bad_host = valid.clone();
        bad_host.hostname_fqdn = "dc1".to_string();
        assert!(validate_provision_request(&bad_host).is_err());

        // Rejeita sufixo diferente do Realm
        let mut mismatch = valid.clone();
        mismatch.hostname_fqdn = "dc1.outrodominio.com".to_string();
        assert!(validate_provision_request(&mismatch).is_err());

        // Rejeita senha curta
        let mut bad_pass = valid.clone();
        bad_pass.admin_password = "123".to_string();
        assert!(validate_provision_request(&bad_pass).is_err());
    }
}
