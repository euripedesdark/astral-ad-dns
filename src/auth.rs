use axum::{

    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::api::users::ApiResponse;

pub const DEFAULT_AUTH_SECRET: &str = "dd1f4702cbb4d061075ff7c58c63e3f48a214bf6117e4453ad4ee20b2f48e3ae";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    pub username: String,
    pub provider: String, // "AD", "Linux", "Postgres", "OAuth2"
    pub groups: Vec<String>,
    #[serde(default)]
    pub is_admin: bool,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedOperator {
    pub username: String,
    pub provider: String,
    pub is_admin: bool,
    pub groups: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub provider: Option<String>, // "auto" | "ad" | "linux" | "postgres"
}

#[derive(Serialize, Debug)]
pub struct LoginResponseData {
    pub token: String,
    pub token_type: String,
    pub expires_in: usize,
    pub operator: AuthenticatedOperator,
}

/// Lê o segredo compartilhado de autenticação
pub fn get_auth_secret() -> String {
    if let Ok(sec) = std::env::var("AUTH_TOKEN_SECRET") {
        if !sec.trim().is_empty() {
            return sec;
        }
    }
    if let Ok(sec) = std::env::var("ASTRAL_AUTH_TOKEN_SECRET") {
        if !sec.trim().is_empty() {
            return sec;
        }
    }
    // Tenta ler de /etc/auth-service/auth.env se estiver acessível (root)
    let env_file = Path::new("/etc/auth-service/auth.env");
    if env_file.exists() {
        if let Ok(content) = fs::read_to_string(env_file) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("AUTH_TOKEN_SECRET=") {
                    let val = trimmed.trim_start_matches("AUTH_TOKEN_SECRET=").trim();
                    if !val.is_empty() {
                        return val.to_string();
                    }
                }
            }
        }
    }
    DEFAULT_AUTH_SECRET.to_string()
}

/// Gera um JWT compatível com o astral-auth-service
pub fn issue_jwt(
    username: &str,
    provider: &str,
    groups: Vec<String>,
    is_admin: bool,
    secret: &str,
) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as usize;

    let claims = Claims {
        iss: "auth-service".to_string(),
        sub: username.to_string(),
        identity_id: username.to_string(),
        username: username.to_string(),
        provider: provider.to_string(),
        groups,
        is_admin,
        iat: now,
        exp: now + 3600 * 8, // 8 horas de validade
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("Falha ao assinar JWT: {}", e))
}

/// Valida o JWT contra o segredo compartilhado
pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    // Permite tokens emitidos por "auth-service" ou pelo próprio módulo
    validation.set_issuer(&["auth-service", "astral-ad-dns", "astral-auth-service"]);
    // Desativa validação de audience se não estiver presente no claims do auth-service
    validation.validate_aud = false;

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => Err(format!("Token JWT inválido ou expirado: {}", e)),
    }
}

/// Extrai o token de autenticação dos Headers (Bearer) ou dos Cookies (sso_token / astral_token)
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    // 1. Authorization: Bearer <token>
    if let Some(auth_val) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_val.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    // 2. Cookie: sso_token=... ou astral_token=...
    if let Some(cookie_val) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("sso_token=") {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
                if let Some(token) = part.strip_prefix("astral_token=") {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }

    None
}

// ==============================================================================
// PROVEDOR 1: LINUX LOCAL (SUDO / ROOT)
// ==============================================================================
pub fn authenticate_linux(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha são obrigatórios".to_string());
    }

    // 1. Verifica se o usuário é root ou pertence ao grupo wheel / sudo
    let is_root = user == "root";
    let is_wheel_or_sudo = if !is_root {
        let id_out = Command::new("id")
            .arg("-nG")
            .arg(user)
            .output()
            .map_err(|e| format!("Falha ao verificar grupos do usuário {}: {}", user, e))?;

        if !id_out.status.success() {
            return Err(format!("Usuário do sistema '{}' não encontrado", user));
        }

        let groups_str = String::from_utf8_lossy(&id_out.stdout);
        let in_sudo = groups_str.split_whitespace().any(|g| g == "wheel" || g == "sudo");
        if !in_sudo {
            return Err(format!(
                "Acesso negado: o usuário '{}' não pertence ao grupo 'wheel' ou 'sudo'",
                user
            ));
        }
        true
    } else {
        true
    };

    // 2. Testa a senha do usuário via sudo controlado
    // Como o daemon roda como root, sudo -u <user> sudo -k -S true testa a senha do próprio usuário
    use std::io::Write;
    let mut child = Command::new("sudo")
        .args(["-k", "-S", "-u", user, "sudo", "-k", "-S", "true"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Falha ao invocar subsistema de autenticação sudo: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(pass.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let status = child
        .wait()
        .map_err(|e| format!("Erro no processo de validação de credenciais: {}", e))?;

    if !status.success() {
        return Err("Senha do usuário Linux inválida ou permissão negada".to_string());
    }

    Ok(AuthenticatedOperator {
        username: user.to_string(),
        provider: "Linux".to_string(),
        is_admin: is_wheel_or_sudo || is_root,
        groups: vec!["wheel".to_string(), "sudo".to_string()],
    })
}

// ==============================================================================
// PROVEDOR 2: POSTGRESQL SUPERUSER
// ==============================================================================
pub fn authenticate_postgres(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha do PostgreSQL são obrigatórios".to_string());
    }

    // Executa query de validação de superusuário via psql local
    let out = Command::new("psql")
        .args([
            "-h",
            "127.0.0.1",
            "-U",
            user,
            "-d",
            "postgres",
            "-tAc",
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
        ])
        .env("PGPASSWORD", pass)
        .output()
        .map_err(|e| format!("Falha ao executar cliente PostgreSQL: {}", e))?;

    if !out.status.success() {
        let err_msg = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Falha na autenticação PostgreSQL: {}", err_msg.trim()));
    }

    let is_super = String::from_utf8_lossy(&out.stdout).trim() == "t";
    if !is_super {
        return Err(format!(
            "Acesso negado: o usuário PostgreSQL '{}' não possui privilégios de superusuário (rolsuper=true)",
            user
        ));
    }

    Ok(AuthenticatedOperator {
        username: user.to_string(),
        provider: "Postgres".to_string(),
        is_admin: true,
        groups: vec!["superuser".to_string(), "pg_roles".to_string()],
    })
}

// ==============================================================================
// PROVEDOR 3: SAMBA ACTIVE DIRECTORY / ASTRAL AUTH SERVICE
// ==============================================================================
pub fn authenticate_samba_ad(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha do Active Directory são obrigatórios".to_string());
    }

    // 1. Tenta autenticar via astral-auth-service se estiver rodando (:8181)
    let payload = serde_json::json!({
        "username": user,
        "password": pass,
    });

    let curl_res = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "3",
            "-X",
            "POST",
            "http://127.0.0.1:8181/api/v1/identity/token",
            "-H",
            "Content-Type: application/json",
            "-d",
            &payload.to_string(),
        ])
        .output();

    if let Ok(c_out) = curl_res {
        if c_out.status.success() {
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&c_out.stdout) {
                if let Some(identity) = json_val.get("identity") {
                    let groups: Vec<String> = identity
                        .get("groups")
                        .and_then(|g| g.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    let is_admin = groups.iter().any(|g| {
                        let lower = g.to_lowercase();
                        lower.contains("admin") || lower.contains("administrators")
                    });

                    return Ok(AuthenticatedOperator {
                        username: user.to_string(),
                        provider: "AD".to_string(),
                        is_admin: is_admin || user.eq_ignore_ascii_case("Administrator"),
                        groups,
                    });
                }
            }
        }
    }

    // 2. Fallback: Autenticação direta contra o Samba AD DC via smbclient local
    let out = Command::new("smbclient")
        .args([
            "-L",
            "//127.0.0.1",
            "-U",
            &format!("{}%{}", user, pass),
            "-c",
            "exit",
        ])
        .output()
        .map_err(|e| format!("Falha ao invocar smbclient para autenticação do Samba AD: {}", e))?;

    if !out.status.success() {
        return Err("Usuário ou senha do Samba Active Directory inválidos".to_string());
    }

    // Recupera grupos do usuário no Active Directory
    let grp_out = Command::new("samba-tool")
        .args(["user", "getgroups", user])
        .output();

    let mut groups = Vec::new();
    let mut is_admin = user.eq_ignore_ascii_case("Administrator");

    if let Ok(g_out) = grp_out {
        let lines = String::from_utf8_lossy(&g_out.stdout);
        for line in lines.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                groups.push(trimmed.to_string());
                let lower = trimmed.to_lowercase();
                if lower.contains("admin") || lower.contains("administrators") {
                    is_admin = true;
                }
            }
        }
    }

    Ok(AuthenticatedOperator {
        username: user.to_string(),
        provider: "AD".to_string(),
        is_admin,
        groups,
    })
}

/// Tenta autenticação em múltiplos provedores ou no provedor específico
pub fn authenticate_any(
    username: &str,
    password: &str,
    provider: Option<&str>,
) -> Result<AuthenticatedOperator, String> {
    match provider.unwrap_or("auto") {
        "linux" => authenticate_linux(username, password),
        "postgres" => authenticate_postgres(username, password),
        "ad" | "samba" => authenticate_samba_ad(username, password),
        _ => {
            // Modo "auto": Tenta Samba AD primeiro, depois Linux Sudo, depois PostgreSQL
            if let Ok(op) = authenticate_samba_ad(username, password) {
                return Ok(op);
            }
            if let Ok(op) = authenticate_linux(username, password) {
                return Ok(op);
            }
            if let Ok(op) = authenticate_postgres(username, password) {
                return Ok(op);
            }
            Err("Credenciais inválidas em todas as fontes (Samba AD, Linux Sudo e PostgreSQL Superuser)".to_string())
        }
    }
}

// ==============================================================================
// EXTRACTOR AXUM PARA ROTAS PROTEGIDAS
// ==============================================================================

impl<S> FromRequestParts<S> for AuthenticatedOperator
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ApiResponse<()>>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token_opt = extract_token(&parts.headers);

        let token = match token_opt {
            Some(t) => t,
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ApiResponse {
                        success: false,
                        message: "Autenticação obrigatória. Forneça Bearer Token ou Cookie de sessão válido."
                            .to_string(),
                        data: None,
                        dry_run: false,
                        correlation_id: None,
                    }),
                ));
            }
        };

        let secret = get_auth_secret();
        match verify_jwt(&token, &secret) {
            Ok(claims) => {
                let is_admin = claims.is_admin
                    || claims.username.eq_ignore_ascii_case("Administrator")
                    || claims.username == "root"
                    || claims.provider == "Linux"
                    || claims.provider == "Postgres"
                    || claims.groups.iter().any(|g| {
                        let l = g.to_lowercase();
                        l.contains("admin") || l.contains("superuser")
                    });

                Ok(AuthenticatedOperator {
                    username: claims.username,
                    provider: claims.provider,
                    is_admin,
                    groups: claims.groups,
                })
            }
            Err(err_msg) => Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    message: format!("Sessão expirada ou token inválido: {}", err_msg),
                    data: None,
                    dry_run: false,
                    correlation_id: None,
                }),
            )),
        }
    }
}

// ==============================================================================
// HANDLERS REST DE AUTENTICAÇÃO (/api/auth/*)
// ==============================================================================

pub async fn login_handler(
    _headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let secret = get_auth_secret();

    match authenticate_any(&payload.username, &payload.password, payload.provider.as_deref()) {
        Ok(operator) => {
            info!(
                "Login bem-sucedido para operador '{}' via provedor '{}'",
                operator.username, operator.provider
            );

            let token = match issue_jwt(
                &operator.username,
                &operator.provider,
                operator.groups.clone(),
                operator.is_admin,
                &secret,
            ) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::<()> {
                            success: false,
                            message: format!("Erro ao gerar token: {}", e),
                            data: None,
                            dry_run: false,
                            correlation_id: None,
                        }),
                    )
                        .into_response();
                }
            };

            let mut resp_headers = HeaderMap::new();
            let sso_cookie = format!(
                "sso_token={}; Path=/; SameSite=Lax; Max-Age=28800",
                token
            );
            let astral_cookie = format!(
                "astral_token={}; Path=/; SameSite=Lax; Max-Age=28800",
                token
            );

            if let Ok(v) = HeaderValue::from_str(&sso_cookie) {
                resp_headers.append(header::SET_COOKIE, v);
            }
            if let Ok(v) = HeaderValue::from_str(&astral_cookie) {
                resp_headers.append(header::SET_COOKIE, v);
            }

            let resp_data = LoginResponseData {
                token,
                token_type: "Bearer".to_string(),
                expires_in: 28800,
                operator,
            };

            (
                StatusCode::OK,
                resp_headers,
                Json(ApiResponse {
                    success: true,
                    message: "Autenticação realizada com sucesso".to_string(),
                    data: Some(resp_data),
                    dry_run: false,
                    correlation_id: None,
                }),
            )
                .into_response()
        }
        Err(err) => {
            warn!("Tentativa de login falhou para '{}': {}", payload.username, err);
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()> {
                    success: false,
                    message: err,
                    data: None,
                    dry_run: false,
                    correlation_id: None,
                }),
            )
                .into_response()
        }
    }
}

pub async fn me_handler(operator: AuthenticatedOperator) -> Json<ApiResponse<AuthenticatedOperator>> {
    Json(ApiResponse {
        success: true,
        message: "Operador autenticado".to_string(),
        data: Some(operator),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn logout_handler() -> Response {
    let mut resp_headers = HeaderMap::new();
    let clear_sso = "sso_token=; Path=/; SameSite=Lax; Max-Age=0";
    let clear_astral = "astral_token=; Path=/; SameSite=Lax; Max-Age=0";
    if let Ok(v) = HeaderValue::from_str(clear_sso) {
        resp_headers.append(header::SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(clear_astral) {
        resp_headers.append(header::SET_COOKIE, v);
    }

    (
        StatusCode::OK,
        resp_headers,
        Json(ApiResponse::<()> {
            success: true,
            message: "Sessão encerrada com sucesso".to_string(),
            data: None,
            dry_run: false,
            correlation_id: None,
        }),
    )
        .into_response()
}

pub async fn providers_handler() -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse {
        success: true,
        message: "Provedores de autenticação suportados".to_string(),
        data: Some(serde_json::json!([
            {
                "id": "ad",
                "name": "Samba Active Directory / OAuth2",
                "description": "Autenticação corporativa via Kerberos/LDAP ou token SSO do auth-service"
            },
            {
                "id": "linux",
                "name": "Linux Local (Root / Sudo)",
                "description": "Usuário local do sistema operacional com privilégios no grupo wheel ou sudo"
            },
            {
                "id": "postgres",
                "name": "PostgreSQL Superuser",
                "description": "Superusuário com atributo rolsuper=true no banco PostgreSQL local"
            }
        ])),
        dry_run: false,
        correlation_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_issuance_and_verification() {
        let secret = "my_super_secret_testing_key_1234567890";
        let token = issue_jwt(
            "admin_test",
            "Linux",
            vec!["wheel".into()],
            true,
            secret,
        )
        .expect("token should be issued");

        let claims = verify_jwt(&token, secret).expect("token should be verified");
        assert_eq!(claims.username, "admin_test");
        assert_eq!(claims.provider, "Linux");
        assert!(claims.is_admin);
        assert_eq!(claims.groups, vec!["wheel".to_string()]);
    }

    #[test]
    fn test_rejects_invalid_secret() {
        let secret1 = "secret_one_12345678901234567890";
        let secret2 = "secret_two_12345678901234567890";
        let token = issue_jwt("user", "AD", vec![], false, secret1).unwrap();
        assert!(verify_jwt(&token, secret2).is_err());
    }
}
