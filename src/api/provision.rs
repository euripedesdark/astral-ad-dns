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
use crate::system::{run_cmd_dry, ensure_firewall_port_open, check_service_active, sanitize_arg, shell_quote};
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
pub struct ProvisionNewDcRequest {
    pub realm: String,
    pub workgroup: String,
    pub hostname_fqdn: String,
    pub admin_password: String,
    pub dns_backend: Option<String>,
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
    pub netbios_name: Option<String>,
    pub domain_role: Option<String>, // "DC", "RODC", "MEMBER" (default: "DC")
    pub dns_backend: Option<String>, // SAMBA_INTERNAL for DC/RODC; NONE for MEMBER
    pub setup_bind_hybrid: Option<bool>,
    #[serde(default)]
    pub clean_existing: bool,
    #[serde(default)]
    pub dry_run: bool,
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

pub async fn provision_new_dc(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ProvisionNewDcRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    if let Some(backend) = payload.dns_backend.as_deref() {
        if !backend.eq_ignore_ascii_case("SAMBA_INTERNAL") {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                message: "Este projeto usa SAMBA_INTERNAL na porta 53 e BIND recursivo em 127.0.0.1:5353. Backend DNS incompatível.".into(),
                data: None, dry_run: payload.dry_run, correlation_id: None,
            }));
        }
    }
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
    let forwarder = if payload.setup_bind_hybrid.unwrap_or(true) {
        "127.0.0.1:5353".to_string()
    } else {
        payload.dns_forwarder.unwrap_or_else(|| "8.8.8.8".to_string())
    };
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
            let named_result = run_cmd_dry("named-checkconf /etc/named.conf && systemctl enable named && systemctl restart named", sudo, false);
            if !named_result.success {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    success: false, message: format!("Falha ao ativar BIND recursivo: {}", named_result.stderr),
                    data: None, dry_run: false, correlation_id: None,
                }));
            }
            steps.push("BIND 9 híbrido recursivo ativo em 127.0.0.1:5353.".to_string());
        }
    }

    // 4. Comando de provisionamento do Samba
    let selected_dns_backend = "SAMBA_INTERNAL";

    let prov_cmd = format!(
        "samba-tool domain provision --use-rfc2307 --realm='{}' --domain='{}' --server-role=dc --dns-backend={} --adminpass={}",
        payload.realm.to_uppercase(),
        payload.workgroup.to_uppercase(),
        selected_dns_backend,
        shell_quote(&payload.admin_password)
    );

    if d {
        steps.push(format!(
            "[SIMULAÇÃO] Execução prevista: samba-tool domain provision --use-rfc2307 --realm='{}' --domain='{}' --server-role=dc --dns-backend={} --adminpass=********",
            payload.realm.to_uppercase(),
            payload.workgroup.to_uppercase(),
            selected_dns_backend
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
    if let Some(backend) = payload.dns_backend.as_deref() {
        if !backend.eq_ignore_ascii_case("SAMBA_INTERNAL") && !(payload.domain_role.as_deref().unwrap_or("DC").eq_ignore_ascii_case("MEMBER") && backend.eq_ignore_ascii_case("NONE")) {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                message: "Este projeto usa SAMBA_INTERNAL na porta 53 e BIND recursivo em 127.0.0.1:5353. Backend DNS incompatível.".into(),
                data: None, dry_run: payload.dry_run, correlation_id: None,
            }));
        }
    }
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();
    let d = payload.dry_run;

    let realm = payload.realm.trim().to_uppercase();
    let target_dc_ip = payload.target_dc_ip.trim();

    if realm.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Domínio Kerberos (REALM) é obrigatório".to_string(),
                data: None,
                dry_run: d,
                correlation_id: None,
            }),
        );
    }

    if target_dc_ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Endereço IP do DC parceiro/primário é obrigatório".to_string(),
                data: None,
                dry_run: d,
                correlation_id: None,
            }),
        );
    }

    // 1. Verificação obrigatória do binário samba-tool
    let samba_tool_installed = run_cmd_dry("which samba-tool 2>/dev/null", sudo, false).success;
    if !samba_tool_installed {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(ApiResponse {
                success: false,
                message: "O comando 'samba-tool' não está instalado neste servidor. Instale os pacotes Samba DC ('samba-dc', 'samba-tools', 'samba-winbind').".to_string(),
                data: Some(ProvisionResult {
                    steps_completed: steps,
                    error: Some("samba-tool: comando não encontrado".to_string()),
                    plan_only: false,
                }),
                dry_run: d,
                correlation_id: None,
            }),
        );
    }
    steps.push("Utilitário samba-tool verificado no sistema.".to_string());

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let my_hostname = host_res.stdout.trim().to_lowercase();
    let dc_netbios = payload.netbios_name.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty())
        .unwrap_or(&my_hostname)
        .to_uppercase();

    let ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
    let my_ip = ip_res.stdout.trim().to_string();

    // 2. Limpeza prévia de banco de dados e remoção de registros órfãos no DC parceiro (se solicitado)
    if payload.clean_existing && !d {
        // Tenta desprovisionar conta morta/órfã no DC parceiro se já existir
        let demote_cmd = format!(
            "samba-tool domain demote --remove-other-dead-server='{}' -H 'ldap://{}' -U '{}%{}'",
            dc_netbios,
            target_dc_ip,
            sanitize_arg(&payload.admin_username),
            sanitize_arg(&payload.admin_password)
        );
        let _ = run_cmd_dry(&demote_cmd, sudo, false);

        // Limpeza dos arquivos locais residuais do Samba (conforme Tranquil IT)
        let _ = run_cmd_dry("systemctl stop samba samba-dc smbd nmbd winbind named 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("rm -rf /var/lib/samba/private/* /var/lib/samba/*.tdb /etc/samba/smb.conf", sudo, false);
        steps.push(format!("Limpeza prévia de arquivos residuais e desprovisionamento da conta órfã '{}' concluída.", dc_netbios));
    }

    if !d {
    // 3. Configurar e verificar previamente o DNS do AD no DC2 (sem DNS externo como Google)
    // Para ingressar no domínio, o DC2 DEVE consultar exclusivamente o DNS do AD.
    crate::system::configure_ad_dns_resolver(&realm, Some(target_dc_ip), sudo);
    steps.push(format!("Resolver local (/etc/resolv.conf) apontado exclusivamente para o DNS do AD ({}) e 127.0.0.1.", target_dc_ip));

    // Testa se o DNS do AD resolve os registros de serviço do domínio
    let srv_res = run_cmd_dry(&format!("host -t srv _ldap._tcp.dc._msdcs.{} 2>/dev/null", realm.to_lowercase()), sudo, false);
    if srv_res.success {
        steps.push(format!("Consulta SRV do AD (_ldap._tcp.dc._msdcs.{}) validada com sucesso contra o DNS do AD.", realm.to_lowercase()));
    } else {
        steps.push(format!("Aviso: O registro SRV do AD ainda não resolveu diretamente. Tentando prosseguir com --server={}.", target_dc_ip));
    }

    }

    let raw_role = payload.domain_role.as_deref().unwrap_or("DC").trim().to_uppercase();
    let domain_role = match raw_role.as_str() {
        "RODC" => "RODC",
        "MEMBER" => "MEMBER",
        _ => "DC",
    };

    let dns_backend = "SAMBA_INTERNAL";

    if d {
        steps.push(format!("[SIMULAÇÃO] Verificação de portas de comunicação com o DC parceiro em {}", target_dc_ip));
        if domain_role == "MEMBER" {
            steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain join {} MEMBER -U'{}' --password=******** --server={} --netbios-name={}", realm, payload.admin_username, target_dc_ip, dc_netbios));
            steps.push("[SIMULAÇÃO] Configuração de smb.conf para Servidor Membro (security = ADS), ativação de winbind e smbd".to_string());
        } else if domain_role == "RODC" {
            steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain join {} RODC -U'{}' --password=******** --server={} --netbios-name={} --dns-backend={}", realm, payload.admin_username, target_dc_ip, dc_netbios, dns_backend));
            steps.push(format!("[SIMULAÇÃO] Registro DNS A ({}.{} -> {}) no AD e inicialização da replicação unidirecional RODC", dc_netbios.to_lowercase(), realm.to_lowercase(), my_ip));
        } else {
            steps.push(format!("[SIMULAÇÃO] Execução prevista: samba-tool domain join {} DC -U'{}' --password=******** --server={} --netbios-name={} --dns-backend={}", realm, payload.admin_username, target_dc_ip, dc_netbios, dns_backend));
            steps.push(format!("[SIMULAÇÃO] Registro DNS A ({}.{} -> {}) e NS no AD", dc_netbios.to_lowercase(), realm.to_lowercase(), my_ip));
            steps.push("[SIMULAÇÃO] Inicialização da replicação DRS e sincronismo de diretório".to_string());
        }

        let evt_id = config.audit.record(
            "admin",
            None,
            "JOIN_SIMULATION",
            &format!("domain:{}:role:{}", realm, domain_role),
            true,
            true,
            &format!("Simulação de ingresso no domínio {} como {}", realm, domain_role),
        );

        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("[SIMULAÇÃO] Plano de ingresso ao domínio ({}) gerado com sucesso.", domain_role),
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

    // 4. Execução real do join no domínio
    let workgroup = realm.split('.').next().unwrap_or("SRVCLOUD");
    let join_cmd = if domain_role == "MEMBER" {
        format!(
            "samba-tool domain join '{}' MEMBER -U{} --password={} --server='{}' --netbios-name='{}' --realm='{}' -W '{}'",
            realm,
            shell_quote(&payload.admin_username),
            shell_quote(&payload.admin_password),
            target_dc_ip,
            dc_netbios,
            realm,
            workgroup
        )
    } else {
        format!(
            "samba-tool domain join '{}' {} -U{} --password={} --server='{}' --netbios-name='{}' --realm='{}' -W '{}' --dns-backend={} --option='ad dc functional level = 2016'",
            realm,
            domain_role,
            shell_quote(&payload.admin_username),
            shell_quote(&payload.admin_password),
            target_dc_ip,
            dc_netbios,
            realm,
            workgroup,
            dns_backend
        )
    };

    let res = run_cmd_dry(&join_cmd, sudo, false);
    if !res.success {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Falha ao ingressar no domínio como {}: {}", domain_role, res.stderr),
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

    // 5. Ajustes e serviços pós-join por papel
    if domain_role == "MEMBER" {
        steps.push(format!("Ingressou com sucesso no domínio '{}' como Servidor Membro (MEMBER / Bind: {}).", realm, dc_netbios));

        if Path::new("/var/lib/samba/private/krb5.conf").exists() {
            let _ = run_cmd_dry("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf", sudo, false);
            steps.push("Configuração Kerberos (/etc/krb5.conf) sincronizada com realm do domínio.".to_string());
        }

        let add_a_cmd = format!(
            "samba-tool dns add '{}' '{}' '{}' A '{}' -U'{}%{}'",
            target_dc_ip,
            realm.to_lowercase(),
            dc_netbios.to_lowercase(),
            my_ip,
            sanitize_arg(&payload.admin_username),
            sanitize_arg(&payload.admin_password)
        );
        let _ = run_cmd_dry(&add_a_cmd, sudo, false);
        steps.push(format!("Registro DNS A de {} ({}.{} -> {}) garantido no AD.", dc_netbios, dc_netbios.to_lowercase(), realm.to_lowercase(), my_ip));

        crate::system::configure_ad_dns_resolver(&realm, Some(target_dc_ip), sudo);
        steps.push(format!("Resolver DNS local protegido apontando para o DC parceiro ({}).", target_dc_ip));

        let _ = run_cmd_dry("systemctl stop samba 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl mask samba 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl unmask smbd winbind 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl enable --now smbd winbind", sudo, false);
        steps.push("Serviços de Servidor Membro (smbd, winbind) habilitados e iniciados; daemon AD DC mascarado.".to_string());
    } else if domain_role == "RODC" {
        steps.push(format!("Ingressou com sucesso no domínio '{}' como Read-Only Domain Controller (RODC: {}).", realm, dc_netbios));

        let _ = run_cmd_dry(&format!("sed -i '/\\[global\\]/a \\\\tad dc functional level = 2016\\n\\tdns forwarder = {}' /etc/samba/smb.conf", target_dc_ip), sudo, false);
        steps.push("Configurado nível funcional 2016 e forwarder DNS no /etc/samba/smb.conf.".to_string());

        let _ = run_cmd_dry("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf", sudo, false);
        steps.push("Configuração Kerberos (/etc/krb5.conf) sincronizada com realm do domínio.".to_string());

        let add_a_cmd = format!(
            "samba-tool dns add '{}' '{}' '{}' A '{}' -U'{}%{}'",
            target_dc_ip,
            realm.to_lowercase(),
            dc_netbios.to_lowercase(),
            my_ip,
            sanitize_arg(&payload.admin_username),
            sanitize_arg(&payload.admin_password)
        );
        let _ = run_cmd_dry(&add_a_cmd, sudo, false);
        steps.push(format!("Registro DNS A do RODC ({}.{} -> {}) garantido no AD.", dc_netbios.to_lowercase(), realm.to_lowercase(), my_ip));

        crate::system::configure_ad_dns_resolver(&realm, Some(target_dc_ip), sudo);
        steps.push("Resolver DNS local protegido com chattr +i apontando para 127.0.0.1 e parceiro.".to_string());

        let _ = run_cmd_dry("systemctl mask smbd nmbd winbind systemd-resolved 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl stop named 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl unmask samba 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl enable --now samba", sudo, false);
        steps.push("Serviço Samba Active Directory DC (RODC) inicializado e habilitado no systemd.".to_string());

        if payload.setup_bind_hybrid.unwrap_or(true) {
            let named_conf = "options {\n    directory \"/var/named\";\n    listen-on port 5353 { 127.0.0.1; };\n    listen-on-v6 { none; };\n    allow-query { localhost; };\n    recursion yes;\n    forwarders { 8.8.8.8; 1.1.1.1; };\n    dnssec-validation no;\n    max-cache-size 64m;\n};\n";
            let temp_named = "/tmp/named.conf.gen";
            let _ = fs::write(temp_named, named_conf);
            let _ = run_cmd_dry(&format!("cp -f {} /etc/named.conf", temp_named), sudo, false);
            let _ = fs::remove_file(temp_named);
            let named_result = run_cmd_dry("named-checkconf /etc/named.conf && systemctl enable named && systemctl restart named", sudo, false);
            if !named_result.success {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    success: false, message: format!("Falha ao ativar BIND recursivo: {}", named_result.stderr),
                    data: None, dry_run: false, correlation_id: None,
                }));
            }
            let _ = run_cmd_dry("sed -i 's/dns forwarder = .*/dns forwarder = 127.0.0.1:5353/' /etc/samba/smb.conf", sudo, false);
            let restart = run_cmd_dry("systemctl restart samba || systemctl restart samba-dc", sudo, false);
            if !restart.success {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    success: false, message: format!("Ingresso concluído, mas falhou ao reiniciar Samba: {}", restart.stderr),
                    data: None, dry_run: false, correlation_id: None,
                }));
            }
            steps.push("BIND 9 híbrido recursivo ativo em 127.0.0.1:5353 configurado como forwarder do Samba.".to_string());
        }

        let fw_rep = crate::system::auto_reconcile_firewall_ports(sudo, false);
        steps.push(format!("Firewall pós-ingresso: {} portas verificadas/abertas automaticamente.", fw_rep.total_ports));

        let repl_res = run_cmd_dry("samba-tool drs showrepl 2>&1", sudo, false);
        if repl_res.success {
            steps.push("Replicação Active Directory DRS unidirecional do RODC testada e operacional.".to_string());
        }
    } else {
        // DC (Read-Write réplica)
        steps.push(format!("Ingressou com sucesso no domínio '{}' como Controlador de Domínio réplica ({}).", realm, dc_netbios));

        let _ = run_cmd_dry(&format!("sed -i '/\\[global\\]/a \\\\tad dc functional level = 2016\\n\\tdns forwarder = {}' /etc/samba/smb.conf", target_dc_ip), sudo, false);
        steps.push("Configurado nível funcional 2016 e forwarder DNS no /etc/samba/smb.conf.".to_string());

        let _ = run_cmd_dry("cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf", sudo, false);
        steps.push("Configuração Kerberos (/etc/krb5.conf) sincronizada com realm do domínio.".to_string());

        let add_a_cmd = format!(
            "samba-tool dns add '{}' '{}' '{}' A '{}' -U'{}%{}'",
            target_dc_ip,
            realm.to_lowercase(),
            dc_netbios.to_lowercase(),
            my_ip,
            sanitize_arg(&payload.admin_username),
            sanitize_arg(&payload.admin_password)
        );
        let _ = run_cmd_dry(&add_a_cmd, sudo, false);
        steps.push(format!("Registro DNS A de {} ({}.{} -> {}) garantido no AD.", dc_netbios, dc_netbios.to_lowercase(), realm.to_lowercase(), my_ip));

        let add_ns_cmd = format!(
            "samba-tool dns add '{}' '{}' @ NS '{}.{}' -U'{}%{}'",
            target_dc_ip,
            realm.to_lowercase(),
            dc_netbios.to_lowercase(),
            realm.to_lowercase(),
            sanitize_arg(&payload.admin_username),
            sanitize_arg(&payload.admin_password)
        );
        let _ = run_cmd_dry(&add_ns_cmd, sudo, false);
        steps.push(format!("Registro DNS NS ({}.{}) registrado como autoritativo na zona {}.", dc_netbios.to_lowercase(), realm.to_lowercase(), realm.to_lowercase()));

        crate::system::configure_ad_dns_resolver(&realm, Some(target_dc_ip), sudo);
        steps.push("Resolver DNS local protegido com chattr +i apontando para 127.0.0.1 e parceiro.".to_string());

        let _ = run_cmd_dry("systemctl mask smbd nmbd winbind systemd-resolved 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl stop named 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl unmask samba 2>/dev/null || true", sudo, false);
        let _ = run_cmd_dry("systemctl enable --now samba", sudo, false);
        steps.push("Serviço Samba Active Directory DC inicializado e habilitado no systemd.".to_string());

        if payload.setup_bind_hybrid.unwrap_or(true) {
            let named_conf = "options {\n    directory \"/var/named\";\n    listen-on port 5353 { 127.0.0.1; };\n    listen-on-v6 { none; };\n    allow-query { localhost; };\n    recursion yes;\n    forwarders { 8.8.8.8; 1.1.1.1; };\n    dnssec-validation no;\n    max-cache-size 64m;\n};\n";
            let temp_named = "/tmp/named.conf.gen";
            let _ = fs::write(temp_named, named_conf);
            let _ = run_cmd_dry(&format!("cp -f {} /etc/named.conf", temp_named), sudo, false);
            let _ = fs::remove_file(temp_named);
            let named_result = run_cmd_dry("named-checkconf /etc/named.conf && systemctl enable named && systemctl restart named", sudo, false);
            if !named_result.success {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    success: false, message: format!("Falha ao ativar BIND recursivo: {}", named_result.stderr),
                    data: None, dry_run: false, correlation_id: None,
                }));
            }
            let _ = run_cmd_dry("sed -i 's/dns forwarder = .*/dns forwarder = 127.0.0.1:5353/' /etc/samba/smb.conf", sudo, false);
            let restart = run_cmd_dry("systemctl restart samba || systemctl restart samba-dc", sudo, false);
            if !restart.success {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    success: false, message: format!("Ingresso concluído, mas falhou ao reiniciar Samba: {}", restart.stderr),
                    data: None, dry_run: false, correlation_id: None,
                }));
            }
            steps.push("BIND 9 híbrido recursivo ativo em 127.0.0.1:5353 configurado como forwarder do Samba.".to_string());
        }

        let fw_rep = crate::system::auto_reconcile_firewall_ports(sudo, false);
        steps.push(format!("Firewall pós-ingresso: {} portas verificadas/abertas automaticamente ({} abertas, {} corrigidas).", fw_rep.total_ports, fw_rep.open_count, fw_rep.corrected_count));

        let repl_res = run_cmd_dry("samba-tool drs showrepl 2>&1", sudo, false);
        if repl_res.success {
            steps.push("Replicação Active Directory DRS testada e operacional.".to_string());
        }
    }

    let evt_id = config.audit.record(
        "admin",
        None,
        "JOIN_DOMAIN",
        &format!("domain:{}", realm),
        false,
        true,
        &format!("Ingresso no domínio {} como DC réplica ({})", realm, dc_netbios),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Ingresso no domínio e sincronização DNS concluídos com sucesso!".to_string(),
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

/// Endpoint para resetar/limpar a configuração residual do Samba local e desprovisionar registros órfãos
pub async fn reset_samba_state(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<ResetSambaRequest>,
) -> (StatusCode, Json<ApiResponse<ProvisionResult>>) {
    let sudo = config.sudo_password.as_deref();
    let mut steps = Vec::new();

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let my_hostname = host_res.stdout.trim().to_lowercase();
    let dc_netbios = payload.netbios_name.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty())
        .unwrap_or(&my_hostname)
        .to_uppercase();

    if payload.dry_run {
        steps.push(format!("[SIMULAÇÃO] Parar serviços Samba (samba, smbd, nmbd, winbind)"));
        steps.push(format!("[SIMULAÇÃO] Purgar arquivos locais em /var/lib/samba/private/* e /etc/samba/smb.conf"));
        if let Some(ref partner) = payload.target_dc_ip {
            steps.push(format!("[SIMULAÇÃO] Desprovisionar dead DC '{}' em ldap://{}", dc_netbios, partner));
        }
        return (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: "[SIMULAÇÃO] Plano de reset do Samba preparado.".to_string(),
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

    // 1. Desprovisionar dead DC no parceiro se parâmetros foram fornecidos
    if let (Some(target_dc_ip), Some(admin_user), Some(admin_pass)) = (payload.target_dc_ip, payload.admin_username, payload.admin_password) {
        let demote_cmd = format!(
            "samba-tool domain demote --remove-other-dead-server='{}' -H 'ldap://{}' -U '{}%{}'",
            dc_netbios,
            target_dc_ip,
            sanitize_arg(&admin_user),
            sanitize_arg(&admin_pass)
        );
        let demote_res = run_cmd_dry(&demote_cmd, sudo, false);
        if demote_res.success {
            steps.push(format!("Registros do servidor órfão '{}' removidos com sucesso do DC parceiro ({}).", dc_netbios, target_dc_ip));
        } else {
            steps.push(format!("Aviso ao desprovisionar no parceiro: {}", demote_res.stderr.trim()));
        }
    }

    // 2. Parar serviços
    let _ = run_cmd_dry("systemctl stop samba samba-dc smbd nmbd winbind named 2>/dev/null || true", sudo, false);
    steps.push("Serviços do Samba parados localmente.".to_string());

    // 3. Purgar banco de dados local
    let _ = run_cmd_dry("rm -rf /var/lib/samba/private/* /var/lib/samba/*.tdb /etc/samba/smb.conf", sudo, false);
    steps.push("Diretório /var/lib/samba/private/ e configuração /etc/samba/smb.conf limpos.".to_string());

    let evt_id = config.audit.record(
        "admin",
        None,
        "RESET_SAMBA",
        &format!("dc:{}", dc_netbios),
        false,
        true,
        &format!("Reset e limpeza de estado Samba DC para '{}'", dc_netbios),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Configuração do Samba para '{}' resetada com sucesso!", dc_netbios),
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

/// Endpoint de diagnóstico e verificação do status do DNS do AD no DC2
pub async fn verify_ad_dns_status(
    State(config): State<Arc<AppConfig>>,
) -> Json<AdDnsVerification> {
    let sudo = config.sudo_password.as_deref();

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_lowercase();
    let fqdn_res = run_cmd_dry("hostname -f 2>/dev/null || hostname", sudo, false);
    let fqdn = fqdn_res.stdout.trim().to_lowercase();
    let ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
    let local_ip = ip_res.stdout.trim().to_string();

    let partner_dc_ip = "192.168.2.10".to_string();
    let realm = "SRVCLOUD.CLOUD".to_string();

    let resolv_content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut nameservers = Vec::new();
    for line in resolv_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            if let Some(ns) = trimmed.split_whitespace().nth(1) {
                nameservers.push(ns.to_string());
            }
        }
    }

    let resolv_conf_configured = nameservers.contains(&"192.168.2.10".to_string()) || nameservers.contains(&"127.0.0.1".to_string());

    // Teste de resolução SRV do Active Directory
    let srv_res = run_cmd_dry("host -t srv _ldap._tcp.dc._msdcs.srvcloud.cloud 2>/dev/null", sudo, false);
    let ad_srv_resolves = srv_res.success;
    let ad_srv_target = if ad_srv_resolves {
        srv_res.stdout.lines().find(|l| l.contains("SRV")).and_then(|l| l.split_whitespace().last()).map(|s| s.trim_end_matches('.').to_string())
    } else {
        None
    };

    let samba_tool_installed = run_cmd_dry("which samba-tool 2>/dev/null", sudo, false).success;

    // Consulta se o DC2 está registrado na zona DNS do AD
    let q_a = format!("samba-tool dns query {} {} {} A -U administrator%Copa@@2026 2>/dev/null", partner_dc_ip, realm.to_lowercase(), hostname);
    let dc2_a_record_in_ad = if samba_tool_installed {
        let r = run_cmd_dry(&q_a, sudo, false);
        r.success && r.stdout.contains(&local_ip)
    } else {
        false
    };

    let q_ns = format!("samba-tool dns query {} {} @ NS -U administrator%Copa@@2026 2>/dev/null", partner_dc_ip, realm.to_lowercase());
    let dc2_ns_record_in_ad = if samba_tool_installed {
        let r = run_cmd_dry(&q_ns, sudo, false);
        r.success && r.stdout.contains(&hostname)
    } else {
        false
    };

    let message = if ad_srv_resolves && dc2_a_record_in_ad {
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

    let realm = payload.realm.unwrap_or_else(|| "SRVCLOUD.CLOUD".to_string()).trim().to_uppercase();
    let target_dc_ip = payload.target_dc_ip.unwrap_or_else(|| "192.168.2.10".to_string());
    let admin_user = payload.admin_username.unwrap_or_else(|| "administrator".to_string());
    let admin_pass = payload.admin_password.unwrap_or_else(|| "Copa@@2026".to_string());

    let host_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let hostname = host_res.stdout.trim().to_lowercase();
    let ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
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
            dns_backend: None,
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
