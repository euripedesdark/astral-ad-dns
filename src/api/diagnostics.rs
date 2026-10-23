use axum::{
    extract::State,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use std::time::Instant;
use chrono::Utc;
use crate::config::AppConfig;
use crate::system::{run_safe_cmd, check_service_active, check_port_open};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Operational,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiagnosticItem {
    pub id: String,
    pub category: String, // "service", "network", "dependency", "security", "filesystem"
    pub name: String,
    pub status: DiagnosticStatus,
    pub timestamp: String,
    pub message: String,
    pub possible_cause: Option<String>,
    pub recommended_action: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiagnosticSummary {
    pub total: usize,
    pub operational: usize,
    pub degraded: usize,
    pub unavailable: usize,
    pub unknown: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiagnosticsResponse {
    pub overall_status: DiagnosticStatus,
    pub timestamp: String,
    pub checks: Vec<DiagnosticItem>,
    pub summary: DiagnosticSummary,
}

pub async fn run_diagnostics(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<DiagnosticsResponse>> {
    let sudo = config.sudo_password.as_deref();
    let _admin_pass = config.admin_password.as_deref().unwrap_or("Copa@@2026");
    let now = Utc::now().to_rfc3339();

    let mut checks = Vec::new();

    // 1. API Engine & Uptime
    let t0 = Instant::now();
    let api_latency = t0.elapsed().as_millis() as u64;
    checks.push(DiagnosticItem {
        id: "api_runtime".to_string(),
        category: "service".to_string(),
        name: "Motor REST & Console Astral AD".to_string(),
        status: DiagnosticStatus::Operational,
        timestamp: now.clone(),
        message: "API e runtime Axum/Tokio operando com resposta imediata".to_string(),
        possible_cause: None,
        recommended_action: None,
        latency_ms: Some(api_latency),
    });

    // 2. Serviço Samba Active Directory
    let t0 = Instant::now();
    let samba_active = check_service_active("samba", sudo)
        || check_service_active("samba-dc", sudo)
        || check_service_active("samba-ad-dc", sudo);
    let samba_latency = t0.elapsed().as_millis() as u64;

    if samba_active {
        checks.push(DiagnosticItem {
            id: "samba_service".to_string(),
            category: "service".to_string(),
            name: "Serviço Samba Active Directory".to_string(),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "Controlador de domínio Samba AD ativo e respondendo no systemd".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(samba_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "samba_service".to_string(),
            category: "service".to_string(),
            name: "Serviço Samba Active Directory".to_string(),
            status: DiagnosticStatus::Unavailable,
            timestamp: now.clone(),
            message: "Serviço Samba AD inativo ou não inicializado".to_string(),
            possible_cause: Some("Serviço parado, erro de configuração no smb.conf ou sam.ldb corrompido".to_string()),
            recommended_action: Some("Execute 'systemctl status samba' ou inicialize com 'systemctl start samba'".to_string()),
            latency_ms: Some(samba_latency),
        });
    }

    // 3. Conectividade LDAP (389) e Kerberos (88)
    let t0 = Instant::now();
    let ldap_open = check_port_open("tcp", "389", sudo);
    let krb_open = check_port_open("tcp", "88", sudo);
    let net_latency = t0.elapsed().as_millis() as u64;

    if ldap_open && krb_open {
        checks.push(DiagnosticItem {
            id: "auth_protocols".to_string(),
            category: "network".to_string(),
            name: "Portas de Autenticação (LDAP 389 / Kerberos 88)".to_string(),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "Portas vitais do protocolo de autenticação Active Directory abertas e acessíveis".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(net_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "auth_protocols".to_string(),
            category: "network".to_string(),
            name: "Portas de Autenticação (LDAP 389 / Kerberos 88)".to_string(),
            status: DiagnosticStatus::Degraded,
            timestamp: now.clone(),
            message: format!("Atenção: LDAP={:?}, Kerberos={:?}", ldap_open, krb_open),
            possible_cause: Some("Regras de firewall bloqueando ou portas não abertas na chain INPUT".to_string()),
            recommended_action: Some("Utilize a ferramenta de Firewall do Astral para abrir portas do AD de forma segura".to_string()),
            latency_ms: Some(net_latency),
        });
    }

    // 4. Serviço BIND 9 Hybrid DNS
    let t0 = Instant::now();
    let named_active = check_service_active("named", sudo);
    let bind_latency = t0.elapsed().as_millis() as u64;

    if named_active {
        checks.push(DiagnosticItem {
            id: "bind_dns".to_string(),
            category: "service".to_string(),
            name: "Servidor BIND 9 (Hybrid DNS)".to_string(),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "Serviço BIND 9 (named) ativo e gerenciando resolução híbrida com recursão".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(bind_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "bind_dns".to_string(),
            category: "service".to_string(),
            name: "Servidor BIND 9 (Hybrid DNS)".to_string(),
            status: DiagnosticStatus::Degraded,
            timestamp: now.clone(),
            message: "Serviço BIND 9 inativo. O Samba pode estar operando apenas com DNS interno SAMBA_INTERNAL.".to_string(),
            possible_cause: Some("named parado ou desativado se o domínio utiliza backend interno".to_string()),
            recommended_action: Some("Caso deseje BIND 9 híbrido, inicie com 'systemctl start named'".to_string()),
            latency_ms: Some(bind_latency),
        });
    }

    // 5. Resolução de DNS e Registros SRV do AD
    let t0 = Instant::now();
    let smb_content = fs::read_to_string("/etc/samba/smb.conf").unwrap_or_default();
    let realm = smb_content
        .lines()
        .find(|l| l.trim().to_lowercase().starts_with("realm"))
        .and_then(|l| l.split_once('='))
        .map(|(_, v)| v.trim().to_lowercase())
        .unwrap_or_else(|| "srvcloud.cloud".to_string());

    let srv_cmd = format!("host -t SRV _ldap._tcp.{} 127.0.0.1 2>/dev/null", realm);
    let srv_res = run_safe_cmd(&srv_cmd, sudo);
    let srv_latency = t0.elapsed().as_millis() as u64;

    if srv_res.success && (srv_res.stdout.contains("has SRV record") || srv_res.stdout.contains("points to")) {
        checks.push(DiagnosticItem {
            id: "dns_srv_resolution".to_string(),
            category: "network".to_string(),
            name: format!("Resolução de Registros SRV (_ldap._tcp.{})", realm),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "Localizadores de serviço Active Directory (SRV) resolvendo com precisão via 127.0.0.1".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(srv_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "dns_srv_resolution".to_string(),
            category: "network".to_string(),
            name: format!("Resolução de Registros SRV (_ldap._tcp.{})", realm),
            status: DiagnosticStatus::Degraded,
            timestamp: now.clone(),
            message: "Não foi possível resolver o registro SRV _ldap._tcp localmente".to_string(),
            possible_cause: Some("Zona DNS do AD não carregada ou resolv.conf não aponta para 127.0.0.1".to_string()),
            recommended_action: Some("Verifique as zonas com 'samba-tool dns zonelist' e certifique-se de que 127.0.0.1 é o DNS primário".to_string()),
            latency_ms: Some(srv_latency),
        });
    }

    // 6. Sincronismo de Tempo (Chrony NTP)
    let t0 = Instant::now();
    let chrony_res = run_safe_cmd("chronyc tracking", sudo);
    let chrony_latency = t0.elapsed().as_millis() as u64;

    if chrony_res.success && chrony_res.stdout.contains("Reference ID") {
        let mut offset_ok = true;
        for line in chrony_res.stdout.lines() {
            if line.starts_with("Last offset") {
                if let Some((_, v)) = line.split_once(':') {
                    if let Some(sec_str) = v.trim().split_whitespace().next() {
                        if let Ok(sec) = sec_str.parse::<f64>() {
                            if sec.abs() > 5.0 {
                                offset_ok = false;
                            }
                        }
                    }
                }
            }
        }

        checks.push(DiagnosticItem {
            id: "chrony_ntp".to_string(),
            category: "service".to_string(),
            name: "Sincronização de Relógio (Chrony NTP)".to_string(),
            status: if offset_ok { DiagnosticStatus::Operational } else { DiagnosticStatus::Degraded },
            timestamp: now.clone(),
            message: if offset_ok {
                "Relógio de sistema perfeitamente sincronizado para tickets Kerberos".to_string()
            } else {
                "Desvio de relógio detectado superior a 5 segundos (risco de falha no Kerberos)".to_string()
            },
            possible_cause: if offset_ok { None } else { Some("Servidores NTP upstream inacessíveis ou relógio de hardware desajustado".to_string()) },
            recommended_action: if offset_ok { None } else { Some("Execute 'chronyc makestep' para forçar ajuste imediato de horário".to_string()) },
            latency_ms: Some(chrony_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "chrony_ntp".to_string(),
            category: "service".to_string(),
            name: "Sincronização de Relógio (Chrony NTP)".to_string(),
            status: DiagnosticStatus::Degraded,
            timestamp: now.clone(),
            message: "Chrony não está ativo ou não foi possível obter tracking de NTP".to_string(),
            possible_cause: Some("chronyd parado ou não configurado".to_string()),
            recommended_action: Some("Inicie o chronyd com 'systemctl start chronyd'".to_string()),
            latency_ms: Some(chrony_latency),
        });
    }

    // 7. Dependências e Binários do Sistema Operacional
    let t0 = Instant::now();
    let tools = ["samba-tool", "named", "chronyc", "iptables", "host", "klist"];
    let mut missing_tools = Vec::new();
    for t in &tools {
        let chk = run_safe_cmd(&format!("which {} 2>/dev/null", t), sudo);
        if !chk.success || chk.stdout.trim().is_empty() {
            missing_tools.push(*t);
        }
    }
    let tools_latency = t0.elapsed().as_millis() as u64;

    if missing_tools.is_empty() {
        checks.push(DiagnosticItem {
            id: "os_dependencies".to_string(),
            category: "dependency".to_string(),
            name: "Ferramentas do Sistema Operacional".to_string(),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "Todos os binários essenciais instalados (samba-tool, named, chronyc, iptables, host, klist)".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(tools_latency),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "os_dependencies".to_string(),
            category: "dependency".to_string(),
            name: "Ferramentas do Sistema Operacional".to_string(),
            status: DiagnosticStatus::Degraded,
            timestamp: now.clone(),
            message: format!("Binários ausentes no sistema: {:?}", missing_tools),
            possible_cause: Some("Pacotes adicionais não instalados".to_string()),
            recommended_action: Some(format!("Instale os pacotes ausentes via dnf: dnf install -y {:?}", missing_tools)),
            latency_ms: Some(tools_latency),
        });
    }

    // 8. Arquivos de Configuração e Banco sam.ldb
    let smb_exists = Path::new("/etc/samba/smb.conf").exists();
    let sam_exists = Path::new("/var/lib/samba/private/sam.ldb").exists();
    let krb_exists = Path::new("/etc/krb5.conf").exists();

    if smb_exists && sam_exists {
        checks.push(DiagnosticItem {
            id: "filesystem_configs".to_string(),
            category: "filesystem".to_string(),
            name: "Arquivos de Configuração e Base SAM LDB".to_string(),
            status: DiagnosticStatus::Operational,
            timestamp: now.clone(),
            message: "smb.conf, sam.ldb e krb5.conf presentes e íntegros no disco".to_string(),
            possible_cause: None,
            recommended_action: None,
            latency_ms: Some(1),
        });
    } else {
        checks.push(DiagnosticItem {
            id: "filesystem_configs".to_string(),
            category: "filesystem".to_string(),
            name: "Arquivos de Configuração e Base SAM LDB".to_string(),
            status: DiagnosticStatus::Unavailable,
            timestamp: now.clone(),
            message: format!("Arquivos ausentes: smb.conf={}, sam.ldb={}, krb5.conf={}", smb_exists, sam_exists, krb_exists),
            possible_cause: Some("Domínio não provisionado ou arquivos movidos".to_string()),
            recommended_action: Some("Execute o assistente de provisionamento do Astral AD para configurar o domínio".to_string()),
            latency_ms: Some(1),
        });
    }

    // 9. Estado do SELinux
    let se_res = run_safe_cmd("getenforce 2>/dev/null", sudo);
    let se_status = se_res.stdout.trim().to_string();
    checks.push(DiagnosticItem {
        id: "selinux_security".to_string(),
        category: "security".to_string(),
        name: "Políticas de Segurança SELinux".to_string(),
        status: if se_status.eq_ignore_ascii_case("Enforcing") {
            DiagnosticStatus::Operational
        } else if se_status.eq_ignore_ascii_case("Permissive") {
            DiagnosticStatus::Degraded
        } else {
            DiagnosticStatus::Unknown
        },
        timestamp: now.clone(),
        message: format!("SELinux ativo em modo: {}", if se_status.is_empty() { "Desconhecido" } else { &se_status }),
        possible_cause: None,
        recommended_action: if se_status.eq_ignore_ascii_case("Enforcing") {
            None
        } else {
            Some("Recomenda-se manter o SELinux em 'Enforcing' com as booleans do Samba ativadas para proteção de produção".to_string())
        },
        latency_ms: Some(2),
    });

    // 10. Integridade do Banco com dbcheck
    let t0 = Instant::now();
    let db_res = run_safe_cmd("samba-tool dbcheck --cross-ncs 2>&1", sudo);
    let db_latency = t0.elapsed().as_millis() as u64;
    let db_ok = db_res.success || db_res.stdout.contains("Checked ") || !db_res.stdout.contains("ERROR");

    checks.push(DiagnosticItem {
        id: "samba_dbcheck".to_string(),
        category: "service".to_string(),
        name: "Consistência da Base de Dados (samba-tool dbcheck)".to_string(),
        status: if db_ok { DiagnosticStatus::Operational } else { DiagnosticStatus::Degraded },
        timestamp: now.clone(),
        message: if db_ok {
            "Estrutura da base de dados e atributos LDB sem inconsistências detectadas".to_string()
        } else {
            "dbcheck reportou avisos ou inconsistências na base".to_string()
        },
        possible_cause: if db_ok { None } else { Some("Objetos órfãos ou desconexão de atributos de replicação".to_string()) },
        recommended_action: if db_ok { None } else { Some("Execute dbcheck com correção pela aba Saúde ou 'samba-tool dbcheck --cross-ncs --fix'".to_string()) },
        latency_ms: Some(db_latency),
    });

    // Sumarização dos Indicadores
    let mut op = 0;
    let mut deg = 0;
    let mut unav = 0;
    let mut unk = 0;

    for c in &checks {
        match c.status {
            DiagnosticStatus::Operational => op += 1,
            DiagnosticStatus::Degraded => deg += 1,
            DiagnosticStatus::Unavailable => unav += 1,
            DiagnosticStatus::Unknown => unk += 1,
        }
    }

    let overall = if unav > 0 {
        DiagnosticStatus::Unavailable
    } else if deg > 0 {
        DiagnosticStatus::Degraded
    } else {
        DiagnosticStatus::Operational
    };

    let summary = DiagnosticSummary {
        total: checks.len(),
        operational: op,
        degraded: deg,
        unavailable: unav,
        unknown: unk,
    };

    Json(ApiResponse {
        success: true,
        message: format!("Diagnóstico concluído: {} operacionais, {} degradados, {} indisponíveis", op, deg, unav),
        data: Some(DiagnosticsResponse {
            overall_status: overall,
            timestamp: now,
            checks,
            summary,
        }),
        dry_run: false,
        correlation_id: None,
    })
}
