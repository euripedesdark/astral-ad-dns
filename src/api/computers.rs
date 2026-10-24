use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::{run_cmd_dry, sanitize_arg, shell_quote, run_ad_operation};
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComputerItem {
    pub name: String,
    pub is_dc: bool,
    pub is_local: bool,
    pub is_primary: bool,
    pub is_rodc: bool,
}

#[derive(Deserialize, Default)]
pub struct DeleteComputerQuery {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub remove_dead_dc: bool,
}

fn ldif_value(ldif: &str, key: &str) -> String {
    ldif.lines().find_map(|line| {
        let (attribute, value) = line.split_once(": ")?;
        if attribute.eq_ignore_ascii_case(key) { Some(value.trim().to_string()) } else { None }
    }).unwrap_or_default()
}

fn is_domain_controller(ldif: &str) -> bool {
    let flags = ldif_value(ldif, "userAccountControl").parse::<u32>().unwrap_or(0);
    flags & 0x2000 != 0 || ldif_value(ldif, "primaryGroupID") == "521"
}

fn fsmo_primary(output: &str) -> Option<String> {
    let line = output.lines().find(|line| line.to_lowercase().starts_with("pdcemulationmasterrole owner:"))?;
    let marker = "cn=ntds settings,cn=";
    let lower = line.to_lowercase();
    let start = lower.find(marker)? + marker.len();
    Some(line[start..].split(',').next()?.to_uppercase())
}

fn configured_primary(sudo: Option<&str>) -> Option<String> {
    let result = run_cmd_dry("samba-tool fsmo show", sudo, false);
    if result.success {
        if let Some(primary) = fsmo_primary(&result.stdout) { return Some(primary); }
    }
    if let Ok(content) = std::fs::read_to_string("/var/lib/astral-ad-dns/primary-dc.json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(name) = value["name"].as_str() { return Some(name.to_uppercase()); }
        }
    }
    std::env::var("ASTRAL_PRIMARY_DC").ok().filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().trim_end_matches('$').split('.').next().unwrap_or("").to_uppercase())
}

fn is_rodc(ldif: &str) -> bool {
    ldif_value(ldif, "primaryGroupID") == "521" ||
        ldif_value(ldif, "userAccountControl").parse::<u32>().unwrap_or(0) & 0x4000000 != 0
}

fn local_netbios(sudo: Option<&str>) -> String {
    let result = run_cmd_dry("testparm -s --parameter-name='netbios name' 2>/dev/null", sudo, false);
    if result.success && !result.stdout.trim().is_empty() {
        result.stdout.trim().to_uppercase()
    } else {
        run_cmd_dry("hostname -s", sudo, false).stdout.trim().to_uppercase()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComputerProperties {
    pub name: String,
    pub hostname: String,
    pub fqdn: String,
    pub domain: String,
    pub ip_address: String,
    pub mac_address: String,
    pub netmask: String,
    pub operating_system: String,
    pub operating_system_version: String,
    pub distinguished_name: String,
    pub is_dc: bool,
    pub when_created: String,
    pub last_logon: String,
    pub raw_ldif: String,
}

pub async fn get_computer_properties(
    Path(computername): Path<String>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<ComputerProperties>>) {
    let sudo = config.sudo_password.as_deref();
    let clean_name = computername.trim_end_matches('$').trim().to_uppercase();

    let ldb_cmd = format!("samba-tool computer show {}", shell_quote(&clean_name));
    let ldb_res = run_cmd_dry(&ldb_cmd, sudo, false);
    let raw_ldif = ldb_res.stdout.clone();

    let mut distinguished_name = format!("CN={},CN=Computers", clean_name);
    let mut dns_hostname = String::new();
    let mut operating_system = "Desconhecido".to_string();
    let mut operating_system_version = String::new();
    let mut when_created = String::new();
    let mut last_logon = String::new();
    let is_dc = is_domain_controller(&raw_ldif);

    for line in raw_ldif.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("dn:") {
            distinguished_name = trimmed.trim_start_matches("dn:").trim().to_string();
        } else if trimmed.starts_with("distinguishedName:") {
            distinguished_name = trimmed.trim_start_matches("distinguishedName:").trim().to_string();
        } else if trimmed.starts_with("dNSHostName:") {
            dns_hostname = trimmed.trim_start_matches("dNSHostName:").trim().to_lowercase();
        } else if trimmed.starts_with("operatingSystem:") {
            operating_system = trimmed.trim_start_matches("operatingSystem:").trim().to_string();
        } else if trimmed.starts_with("operatingSystemVersion:") {
            operating_system_version = trimmed.trim_start_matches("operatingSystemVersion:").trim().to_string();
        } else if trimmed.starts_with("whenCreated:") {
            when_created = trimmed.trim_start_matches("whenCreated:").trim().to_string();
        } else if trimmed.starts_with("lastLogonTimestamp:") {
            last_logon = trimmed.trim_start_matches("lastLogonTimestamp:").trim().to_string();
        }
    }

    // 2. Extrai Realm e FQDN
    let realm = if let Some(idx) = distinguished_name.find("DC=") {
        distinguished_name[idx..]
            .split(',')
            .filter(|p| p.starts_with("DC="))
            .map(|p| p.trim_start_matches("DC="))
            .collect::<Vec<_>>()
            .join(".")
            .to_uppercase()
    } else {
        "SRVCLOUD.CLOUD".to_string()
    };

    let fqdn = if !dns_hostname.is_empty() {
        dns_hostname
    } else {
        format!("{}.{}", clean_name.to_lowercase(), realm.to_lowercase())
    };

    // 3. Resolução de IP
    let host_s_res = run_cmd_dry("hostname -s 2>/dev/null || hostname", sudo, false);
    let my_host = host_s_res.stdout.trim().to_uppercase();
    let mut ip_address = "Não identificado".to_string();

    if clean_name == my_host {
        let ip_res = run_cmd_dry("hostname -I 2>/dev/null | awk '{print $1}'", sudo, false);
        let s = ip_res.stdout.trim();
        if !s.is_empty() {
            ip_address = s.to_string();
        }
    } else {
        // Tenta resolver via DNS primário/local
        let dns_res = run_cmd_dry(&format!("host '{}' 192.168.2.10 2>/dev/null || host '{}' 127.0.0.1 2>/dev/null", fqdn, fqdn), sudo, false);
        for l in dns_res.stdout.lines() {
            if l.contains("has address") {
                if let Some(ip) = l.split_whitespace().last() {
                    ip_address = ip.to_string();
                    break;
                }
            }
        }
        if ip_address == "Não identificado" {
            // Tenta lookup na tabela arp / hosts
            let arp_lookup = run_cmd_dry(&format!("grep -i '{}' /etc/hosts 2>/dev/null | awk '{{print $1}}'", clean_name), sudo, false);
            let s = arp_lookup.stdout.trim();
            if !s.is_empty() {
                ip_address = s.to_string();
            }
        }
    }

    // 4. Resolução de MAC e Máscara
    let mut mac_address = "Não disponível".to_string();
    let mut netmask = "255.255.255.0 (/24)".to_string();

    if ip_address != "Não identificado" {
        if clean_name == my_host {
            let mac_res = run_cmd_dry("cat /sys/class/net/$(ip route show default 2>/dev/null | awk '{print $5}')/address 2>/dev/null", sudo, false);
            let m = mac_res.stdout.trim();
            if !m.is_empty() {
                mac_address = m.to_uppercase();
            }
            let mask_res = run_cmd_dry("ip -o -f inet addr show 2>/dev/null | awk '/scope global/ {print $4}' | head -n 1", sudo, false);
            let m_str = mask_res.stdout.trim();
            if !m_str.is_empty() {
                netmask = format!("Subnet: {}", m_str);
            }
        } else {
            let arp_res = run_cmd_dry(&format!("ip neigh show '{}' 2>/dev/null | awk '{{print $5}}'", ip_address), sudo, false);
            let m = arp_res.stdout.trim();
            if !m.is_empty() && m.contains(':') {
                mac_address = m.to_uppercase();
            } else {
                let arp_all = run_cmd_dry(&format!("arp -an 2>/dev/null | grep '({})' | awk '{{print $4}}'", ip_address), sudo, false);
                let m2 = arp_all.stdout.trim();
                if !m2.is_empty() && m2.contains(':') {
                    mac_address = m2.to_uppercase();
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Propriedades da máquina '{}' obtidas com sucesso", clean_name),
            data: Some(ComputerProperties {
                name: clean_name.clone(),
                hostname: clean_name,
                fqdn,
                domain: realm,
                ip_address,
                mac_address,
                netmask,
                operating_system,
                operating_system_version,
                distinguished_name,
                is_dc,
                when_created,
                last_logon,
                raw_ldif,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}

#[derive(Deserialize, Debug)]
pub struct CreateComputerRequest {
    pub computername: String,
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn list_computers(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<Vec<ComputerItem>>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool computer list", sudo, false);
    if !res.success {
        return Json(ApiResponse {
            success: false,
            message: format!("Falha ao listar computadores: {}", res.stderr),
            data: None,
            dry_run: false,
            correlation_id: None,
        });
    }

    let local = local_netbios(sudo);
    let primary = configured_primary(sudo);
    let computers: Vec<ComputerItem> = res.stdout.lines()
        .map(str::trim).filter(|name| !name.is_empty())
        .map(|name| {
            let clean = name.trim_end_matches('$');
            let details = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(clean)), sudo, false);
            ComputerItem {
                name: name.to_string(),
                is_dc: is_domain_controller(&details.stdout),
                is_rodc: is_rodc(&details.stdout),
                is_local: clean.eq_ignore_ascii_case(&local),
                is_primary: primary.as_deref().map(|p| clean.eq_ignore_ascii_case(p)).unwrap_or(false),
            }
        }).collect();

    Json(ApiResponse {
        success: true,
        message: format!("Recuperados {} computadores", computers.len()),
        data: Some(computers),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn create_computer(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<CreateComputerRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();
    if payload.computername.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Nome do computador é obrigatório".to_string(),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: None,
            }),
        );
    }

    let mut cmd = format!("samba-tool computer create '{}'", sanitize_arg(&payload.computername));
    if let Some(desc) = payload.description {
        cmd.push_str(&format!(" --description='{}'", sanitize_arg(&desc)));
    }

    let res = run_cmd_dry(&cmd, sudo, payload.dry_run);
    let evt_id = config.audit.record(
        "admin",
        None,
        "COMPUTER_CREATE",
        &format!("computer:{}", payload.computername),
        payload.dry_run,
        res.success,
        &format!("Criação de computador '{}'", payload.computername),
    );

    if res.success {
        (
            StatusCode::CREATED,
            Json(ApiResponse {
                success: true,
                message: if payload.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o computador '{}' seria adicionado ao domínio", payload.computername)
                } else {
                    format!("Computador '{}' criado com sucesso", payload.computername)
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
                message: format!("Falha ao criar computador: {}", res.stderr),
                data: None,
                dry_run: payload.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

pub async fn delete_computer(
    _operator: crate::auth::Administrator,
    Path(computername): Path<String>,
    Query(q): Query<DeleteComputerQuery>,
    State(config): State<Arc<AppConfig>>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let sudo = config.sudo_password.as_deref();

    let name = computername.trim().trim_end_matches('$').to_uppercase();
    let fail = |status, message: String| (status, Json(ApiResponse::<()> {
        success: false, message, data: None, dry_run: q.dry_run, correlation_id: None,
    }));
    if name.is_empty() || name.starts_with('-') || name.contains(['\n', '\r', '\0']) {
        return fail(StatusCode::BAD_REQUEST, "Nome de computador inválido".into());
    }
    let local = local_netbios(sudo);
    if local.is_empty() || name.eq_ignore_ascii_case(&local) {
        return fail(StatusCode::FORBIDDEN, "Não é permitido excluir o próprio servidor do AD.".into());
    }
    if configured_primary(sudo).as_deref() == Some(name.as_str()) {
        return fail(StatusCode::FORBIDDEN, "O DC primário não pode ser excluído.".into());
    }
    let details = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&name)), sudo, false);
    if !details.success {
        return fail(StatusCode::BAD_REQUEST, format!("Falha ao consultar computador: {}", details.stderr));
    }
    let cmd = if is_domain_controller(&details.stdout) {
        let primary = configured_primary(sudo);
        if primary.is_none() || primary.as_deref() == Some(name.as_str()) {
            return fail(StatusCode::FORBIDDEN, "DC primário protegido ou primário não identificado. Verifique FSMO/ASTRAL_PRIMARY_DC.".into());
        }
        if !q.remove_dead_dc {
            return fail(StatusCode::CONFLICT, "DC exige despromoção. Para DC permanentemente desativado, confirme a limpeza de metadados.".into());
        }
        let fsmo = run_cmd_dry("samba-tool fsmo show", sudo, false);
        let marker = format!("CN=NTDS SETTINGS,CN={},", name);
        if !fsmo.success || fsmo.stdout.to_uppercase().contains(&marker) {
            return fail(StatusCode::CONFLICT, "Não foi possível liberar o DC: verifique/transfira suas funções FSMO antes da remoção.".into());
        }
        let host = ldif_value(&details.stdout, "dNSHostName");
        if host.is_empty() {
            return fail(StatusCode::CONFLICT, "DC sem dNSHostName: não foi possível verificar seu estado.".into());
        }
        use std::net::{TcpStream, ToSocketAddrs};
        if let Ok(addresses) = (host.as_str(), 389).to_socket_addrs() {
            if addresses.into_iter().any(|addr| TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).is_ok()) {
                return fail(StatusCode::CONFLICT, "DC ainda está acessível. Execute samba-tool domain demote no DC secundário antes de removê-lo.".into());
            }
        }
        format!("samba-tool domain demote --remove-other-dead-server={}", shell_quote(&name))
    } else {
        format!("samba-tool computer delete {}", shell_quote(&name))
    };
    let res = run_cmd_dry(&cmd, sudo, q.dry_run);

    let evt_id = config.audit.record(
        "admin",
        None,
        "COMPUTER_DELETE",
        &format!("computer:{}", computername),
        q.dry_run,
        res.success,
        &format!("Exclusão do computador '{}'", computername),
    );

    if res.success {
        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: if q.dry_run {
                    format!("[SIMULAÇÃO] Simulação: o computador '{}' seria removido do Active Directory", computername)
                } else {
                    format!("Computador '{}' excluído com sucesso", computername)
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
                message: format!("Falha ao excluir computador: {}", res.stderr),
                data: None,
                dry_run: q.dry_run,
                correlation_id: Some(evt_id),
            }),
        )
    }
}

#[derive(Deserialize)]
pub struct DemoteRequest {
    pub admin_username: String,
    pub admin_password: String,
}

pub async fn demote_controller(
    _operator: crate::auth::Administrator,
    Path(computername): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<DemoteRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<String>>>) {
    let sudo = config.sudo_password.as_deref();
    let name = computername.trim_end_matches('$').to_uppercase();
    let fail = |message: String| (StatusCode::BAD_REQUEST, Json(ApiResponse::<Vec<String>> {
        success: false, message, data: None, dry_run: false, correlation_id: None,
    }));
    let Some(primary) = configured_primary(sudo) else { return fail("Não foi possível identificar o DC primário.".into()); };
    if name == primary { return fail("Despromoção do DC primário bloqueada.".into()); }
    if payload.admin_username.trim().is_empty() || payload.admin_password.is_empty() {
        return fail("Informe credenciais administrativas do domínio.".into());
    }
    let details = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&name)), sudo, false);
    if !details.success || !is_domain_controller(&details.stdout) { return fail("Selecione um controlador de domínio existente.".into()); }
    let fsmo = run_cmd_dry("samba-tool fsmo show", sudo, false);
    if !fsmo.success || fsmo.stdout.to_uppercase().contains(&format!("CN=NTDS SETTINGS,CN={},", name)) {
        return fail("Transfira as funções FSMO deste DC antes da despromoção.".into());
    }
    let partner = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&primary)), sudo, false);
    if !partner.success { return fail("Não foi possível consultar o DC primário.".into()); }
    let request = serde_json::json!({
        "target_name": name, "target_hostname": ldif_value(&details.stdout, "dNSHostName"),
        "primary_hostname": ldif_value(&partner.stdout, "dNSHostName"),
        "local": name.eq_ignore_ascii_case(&local_netbios(sudo)),
        "ssh_user": std::env::var("ASTRAL_DC_SSH_USER").unwrap_or_else(|_| "root".into()),
        "admin_username": payload.admin_username, "admin_password": payload.admin_password,
    });
    let result = run_ad_operation("demote", &request, sudo);
    let id = config.audit.record(&_operator.0.username, None, "DC_DEMOTE", &name, false, result.is_ok(), "Despromoção de DC secundário");
    match result {
        Ok(steps) => (StatusCode::OK, Json(ApiResponse { success: true, message: "DC secundário despromovido.".into(), data: Some(steps), dry_run: false, correlation_id: Some(id) })),
        Err(error) => fail(error),
    }
}

#[derive(Deserialize)]
pub struct TransitionRequest {
    pub admin_username: String,
    pub admin_password: String,
    pub action: String,
    #[serde(default)] pub dry_run: bool,
    #[serde(default)] pub rejoin_confirmed: bool,
}

pub async fn transition_controller(
    operator: crate::auth::Administrator,
    Path(computername): Path<String>,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<TransitionRequest>,
) -> (StatusCode, Json<ApiResponse<Vec<String>>>) {
    let sudo = config.sudo_password.as_deref();
    let fail = |message: String| (StatusCode::BAD_REQUEST, Json(ApiResponse::<Vec<String>> {
        success: false, message, data: None, dry_run: payload.dry_run, correlation_id: None,
    }));
    if !["promote_primary", "promote_writable"].contains(&payload.action.as_str()) {
        return fail("Transição inválida.".into());
    }
    let name = computername.trim_end_matches('$').to_uppercase();
    let Some(primary) = configured_primary(sudo) else { return fail("Principal não identificado.".into()); };
    if name == primary { return fail("Selecione um DC secundário; o alvo já é principal.".into()); }
    let details = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&name)), sudo, false);
    if !details.success || !is_domain_controller(&details.stdout) { return fail("Alvo não é um DC válido.".into()); }
    if (payload.action == "promote_primary" && is_rodc(&details.stdout)) || (payload.action == "promote_writable" && !is_rodc(&details.stdout)) {
        return fail("Tipo de DC incompatível com a transição solicitada.".into());
    }
    if payload.admin_username.trim().is_empty() || payload.admin_password.is_empty() {
        return fail("Credenciais administrativas são obrigatórias.".into());
    }
    let partner = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&primary)), sudo, false);
    if !partner.success || is_rodc(&partner.stdout) { return fail("Principal gravável não encontrado.".into()); }
    let realm = run_cmd_dry("testparm -s --parameter-name=realm 2>/dev/null", sudo, false).stdout.trim().to_uppercase();
    let local_name = local_netbios(sudo);
    let observer = run_cmd_dry(&format!("samba-tool computer show {}", shell_quote(&local_name)), sudo, false);
    let request = serde_json::json!({
        "action": payload.action, "target_name": name, "target_hostname": ldif_value(&details.stdout, "dNSHostName"),
        "primary_name": primary, "primary_hostname": ldif_value(&partner.stdout, "dNSHostName"), "realm": realm,
        "observer_hostname": ldif_value(&observer.stdout, "dNSHostName"), "local": name == local_name,
        "ssh_user": std::env::var("ASTRAL_DC_SSH_USER").unwrap_or_else(|_| "root".into()),
        "admin_username": payload.admin_username, "admin_password": payload.admin_password,
        "dry_run": payload.dry_run, "rejoin_confirmed": payload.rejoin_confirmed,
    });
    let result = run_ad_operation("transition", &request, sudo);
    let id = config.audit.record(&operator.0.username, None, "DC_TRANSITION", &name, payload.dry_run, result.is_ok(), &payload.action);
    match result {
        Ok(steps) => (StatusCode::OK, Json(ApiResponse { success: true, message: if payload.dry_run { "Plano de transição validado.".into() } else { "Transição do controlador concluída e validada.".into() }, data: Some(steps), dry_run: payload.dry_run, correlation_id: Some(id) })),
        Err(error) => (StatusCode::BAD_REQUEST, Json(ApiResponse { success: false, message: error, data: None, dry_run: payload.dry_run, correlation_id: Some(id) })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_detection_uses_directory_attributes() {
        assert!(!is_domain_controller("sAMAccountName: DC-DESKTOP$\nuserAccountControl: 4096\nprimaryGroupID: 515"));
        assert!(is_domain_controller("userAccountControl: 532480\nprimaryGroupID: 516"));
        assert!(is_domain_controller("userAccountControl: 67112960\nprimaryGroupID: 521"));
        assert!(!is_domain_controller(""));
    }
}
