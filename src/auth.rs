use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::api::users::ApiResponse;

pub const DEFAULT_AUTH_SECRET: &str = "dd1f4702cbb4d061075ff7c58c63e3f48a214bf6117e4453ad4ee20b2f48e3ae";

fn default_iss() -> String {
    "auth-service".to_string()
}

fn default_provider() -> String {
    "AD".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    #[serde(default = "default_iss")]
    pub iss: String,
    pub sub: String,
    #[serde(rename = "identityId", default)]
    pub identity_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub has_wheel: bool,
    #[serde(default)]
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedOperator {
    pub username: String,
    pub provider: String,
    pub is_admin: bool,
    pub groups: Vec<String>,
    #[serde(default)]
    pub has_wheel: bool,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub provider: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct LoginResponseData {
    pub token: String,
    pub token_type: String,
    pub expires_in: usize,
    pub operator: AuthenticatedOperator,
}

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

    let has_wheel = if provider == "Postgres" {
        false
    } else {
        is_admin || groups.iter().any(|g| g == "wheel" || g == "sudo")
    };

    let claims = Claims {
        iss: "auth-service".to_string(),
        sub: username.to_string(),
        identity_id: username.to_string(),
        username: username.to_string(),
        provider: provider.to_string(),
        groups,
        is_admin,
        has_wheel,
        iat: now,
        exp: now + 3600 * 8,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("Falha ao assinar JWT: {}", e))
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.required_spec_claims.remove("iss");

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => Err(format!("Token JWT inválido ou expirado: {}", e)),
    }
}

pub fn extract_token(headers: &HeaderMap) -> Option<String> {
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

    if let Some(cookie_val) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("ASTRAL_SESSION=") {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
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
// SUBSISTEMA PAM REAL: AUTENTICAÇÃO LINUX (ROOT / WHEEL / SUDO)
// ==============================================================================

type PamHandle = c_void;

#[repr(C)]
#[derive(Copy, Clone)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(
        num_msg: c_int,
        msg: *mut *mut PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

extern "C" fn pam_conversation_callback(
    num_msg: c_int,
    msg: *mut *mut PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return 19; // PAM_CONV_ERR
    }

    unsafe {
        let password = if !appdata_ptr.is_null() {
            CStr::from_ptr(appdata_ptr as *const c_char).to_bytes_with_nul()
        } else {
            b"\0"
        };

        let responses = libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if responses.is_null() {
            return 19;
        }

        for i in 0..num_msg as isize {
            let m = *(*msg.offset(i));
            if m.msg_style == PAM_PROMPT_ECHO_OFF || m.msg_style == PAM_PROMPT_ECHO_ON {
                let resp_str = libc::malloc(password.len()) as *mut c_char;
                if !resp_str.is_null() {
                    ptr::copy_nonoverlapping(password.as_ptr() as *const c_char, resp_str, password.len());
                    (*responses.offset(i)).resp = resp_str;
                    (*responses.offset(i)).resp_retcode = 0;
                }
            }
        }

        *resp = responses;
        PAM_SUCCESS
    }
}

type PamStartFn = unsafe extern "C" fn(
    service_name: *const c_char,
    user: *const c_char,
    pam_conversation: *const PamConv,
    pamh: *mut *mut PamHandle,
) -> c_int;

type PamAuthFn = unsafe extern "C" fn(pamh: *mut PamHandle, flags: c_int) -> c_int;
type PamAcctFn = unsafe extern "C" fn(pamh: *mut PamHandle, flags: c_int) -> c_int;
type PamEndFn = unsafe extern "C" fn(pamh: *mut PamHandle, pam_status: c_int) -> c_int;

pub fn pam_authenticate_user(user: &str, password: &str) -> Result<(), String> {
    unsafe {
        let pam_lib_name = CString::new("libpam.so.0").unwrap();
        let mut handle = libc::dlopen(pam_lib_name.as_ptr(), libc::RTLD_NOW);
        if handle.is_null() {
            let alt_name = CString::new("libpam.so").unwrap();
            handle = libc::dlopen(alt_name.as_ptr(), libc::RTLD_NOW);
        }
        if handle.is_null() {
            return Err("Biblioteca PAM (libpam.so.0) não encontrada no sistema operacional".to_string());
        }

        let pam_start_sym = libc::dlsym(handle, b"pam_start\0".as_ptr() as *const c_char);
        let pam_auth_sym = libc::dlsym(handle, b"pam_authenticate\0".as_ptr() as *const c_char);
        let pam_acct_sym = libc::dlsym(handle, b"pam_acct_mgmt\0".as_ptr() as *const c_char);
        let pam_end_sym = libc::dlsym(handle, b"pam_end\0".as_ptr() as *const c_char);

        if pam_start_sym.is_null() || pam_auth_sym.is_null() || pam_end_sym.is_null() {
            libc::dlclose(handle);
            return Err("Símbolos da API PAM não puderam ser vinculados".to_string());
        }

        let pam_start: PamStartFn = std::mem::transmute(pam_start_sym);
        let pam_auth: PamAuthFn = std::mem::transmute(pam_auth_sym);
        let pam_acct: PamAcctFn = if !pam_acct_sym.is_null() {
            std::mem::transmute(pam_acct_sym)
        } else {
            std::mem::transmute(pam_auth_sym)
        };
        let pam_end: PamEndFn = std::mem::transmute(pam_end_sym);

        let c_user = CString::new(user).map_err(|e| e.to_string())?;
        let c_pass = CString::new(password).map_err(|e| e.to_string())?;

        let services = ["system-auth", "login", "password-auth", "su"];
        let mut last_err = "Credenciais PAM inválidas".to_string();

        for srv in services {
            let c_service = CString::new(srv).unwrap();
            let conv = PamConv {
                conv: pam_conversation_callback,
                appdata_ptr: c_pass.as_ptr() as *mut c_void,
            };

            let mut pamh: *mut PamHandle = ptr::null_mut();
            let start_res = pam_start(c_service.as_ptr(), c_user.as_ptr(), &conv, &mut pamh);
            if start_res == PAM_SUCCESS && !pamh.is_null() {
                let auth_res = pam_auth(pamh, 0);
                if auth_res == PAM_SUCCESS {
                    let acct_res = pam_acct(pamh, 0);
                    pam_end(pamh, PAM_SUCCESS);
                    libc::dlclose(handle);
                    if acct_res == PAM_SUCCESS || acct_res == 12 /* PAM_NEW_AUTHTOK_REQD */ {
                        return Ok(());
                    } else {
                        return Err(format!("Conta Linux bloqueada ou restrita pela política PAM (status: {})", acct_res));
                    }
                } else {
                    last_err = format!("Senha do usuário Linux '{}' incorreta (código PAM: {})", user, auth_res);
                    pam_end(pamh, auth_res);
                }
            }
        }

        libc::dlclose(handle);
        Err(last_err)
    }
}

// ==============================================================================
// PROVEDOR 1: LINUX LOCAL (PAM / ROOT / WHEEL / SUDO)
// ==============================================================================
pub fn authenticate_linux(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha são obrigatórios".to_string());
    }

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
                "Acesso negado: o usuário local '{}' não pertence ao grupo 'wheel' ou 'sudo'",
                user
            ));
        }
        true
    } else {
        true
    };

    pam_authenticate_user(user, pass)?;

    let mut user_groups = vec!["wheel".to_string(), "sudo".to_string()];
    if let Ok(g_out) = Command::new("id").args(["-nG", user]).output() {
        if g_out.status.success() {
            user_groups = String::from_utf8_lossy(&g_out.stdout)
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }

    Ok(AuthenticatedOperator {
        username: user.to_string(),
        provider: "Linux".to_string(),
        is_admin: is_wheel_or_sudo || is_root,
        groups: user_groups,
        has_wheel: is_wheel_or_sudo || is_root,
    })
}

// ==============================================================================
// PROVEDOR 2: POSTGRESQL SUPERUSER
// ==============================================================================
pub fn authenticate_postgres(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha do PostgreSQL são obrigatórios".to_string());
    }

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
        has_wheel: false,
    })
}

// ==============================================================================
// PROVEDOR 3: SAMBA ACTIVE DIRECTORY / ASTRAL AUTH SERVICE
// ==============================================================================
pub fn authenticate_samba_ad(user: &str, pass: &str) -> Result<AuthenticatedOperator, String> {
    if user.trim().is_empty() || pass.is_empty() {
        return Err("Usuário e senha do Active Directory são obrigatórios".to_string());
    }

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

                    let has_wheel = identity
                        .get("hasWheel")
                        .and_then(|v| v.as_bool())
                        .unwrap_or_else(|| {
                            Command::new("id")
                                .args(["-nG", user])
                                .output()
                                .map(|o| String::from_utf8_lossy(&o.stdout).contains("wheel"))
                                .unwrap_or(false)
                        });

                    return Ok(AuthenticatedOperator {
                        username: user.to_string(),
                        provider: "AD".to_string(),
                        is_admin: is_admin || user.eq_ignore_ascii_case("Administrator"),
                        groups,
                        has_wheel,
                    });
                }
            }
        }
    }

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

    let has_wheel = Command::new("id")
        .args(["-nG", user])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wheel"))
        .unwrap_or(false);

    Ok(AuthenticatedOperator {
        username: user.to_string(),
        provider: "AD".to_string(),
        is_admin,
        groups,
        has_wheel,
    })
}

pub fn authenticate_any(
    username: &str,
    password: &str,
    provider: Option<&str>,
) -> Result<AuthenticatedOperator, String> {
    let ad_configured = crate::system::is_ad_configured();

    match provider.unwrap_or("auto") {
        "linux" => authenticate_linux(username, password),
        "postgres" => authenticate_postgres(username, password),
        "ad" | "samba" => authenticate_samba_ad(username, password),
        _ => {
            if !ad_configured {
                return authenticate_linux(username, password);
            }

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
        let token_opt = extract_token(&parts.headers).or_else(|| {
            if let Some(query) = parts.uri.query() {
                for pair in query.split("&") {
                    if let Some((k, v)) = pair.split_once("=") {
                        if k == "token" || k == "sso_token" || k == "astral_token" {
                            return Some(v.to_string());
                        }
                    }
                }
            }
            None
        });

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
                    || claims.groups.iter().any(|g| {
                        let l = g.to_lowercase();
                        l.contains("admin") || l.contains("superuser")
                    });

                let has_wheel = if claims.provider == "Postgres" {
                    false
                } else if claims.has_wheel {
                    true
                } else {
                    Command::new("id")
                        .args(["-nG", &claims.username])
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wheel"))
                        .unwrap_or(false)
                };

                Ok(AuthenticatedOperator {
                    username: claims.username,
                    provider: claims.provider,
                    is_admin,
                    groups: claims.groups,
                    has_wheel,
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
            let session_cookie = format!(
                "ASTRAL_SESSION={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800",
                token
            );
            let sso_cookie = format!(
                "sso_token={}; Path=/; SameSite=Lax; Max-Age=28800",
                token
            );
            let astral_cookie = format!(
                "astral_token={}; Path=/; SameSite=Lax; Max-Age=28800",
                token
            );

            if let Ok(v) = HeaderValue::from_str(&session_cookie) {
                resp_headers.append(header::SET_COOKIE, v);
            }
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
    let clear_session = "ASTRAL_SESSION=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    let clear_sso = "sso_token=; Path=/; SameSite=Lax; Max-Age=0";
    let clear_astral = "astral_token=; Path=/; SameSite=Lax; Max-Age=0";
    if let Ok(v) = HeaderValue::from_str(clear_session) {
        resp_headers.append(header::SET_COOKIE, v);
    }
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
    let ad_configured = crate::system::is_ad_configured();
    let recommended = if ad_configured { "ad" } else { "linux" };

    Json(ApiResponse {
        success: true,
        message: "Provedores de autenticação suportados".to_string(),
        data: Some(serde_json::json!({
            "ad_configured": ad_configured,
            "recommended": recommended,
            "providers": [
                {
                    "id": "ad",
                    "name": "Samba Active Directory / OAuth2",
                    "description": "Autenticação corporativa via Kerberos/LDAP ou token SSO do auth-service"
                },
                {
                    "id": "linux",
                    "name": "Linux Local (Root / Sudo / PAM)",
                    "description": "Usuário local do sistema operacional validado via PAM real (root ou membros do grupo wheel/sudo)"
                },
                {
                    "id": "postgres",
                    "name": "PostgreSQL Superuser",
                    "description": "Superusuário com atributo rolsuper=true no banco PostgreSQL local"
                }
            ]
        })),
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
        .expect("JWT issue failed");

        let claims = verify_jwt(&token, secret).expect("JWT verify failed");
        assert_eq!(claims.username, "admin_test");
        assert_eq!(claims.provider, "Linux");
        assert!(claims.is_admin);
        assert!(claims.has_wheel);
    }
}
