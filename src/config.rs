use std::env;
use std::sync::Arc;
use crate::audit::AuditTrail;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: String,
    pub sudo_password: Option<String>,
    pub admin_password: Option<String>,
    pub web_dist_path: String,
    pub audit: Arc<AuditTrail>,
    #[allow(dead_code)]
    pub auth_secret: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let bind_addr = env::var("ASTRAL_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8095".to_string());
        let sudo_password = env::var("ASTRAL_SUDO_PASS")
            .ok()
            .or_else(|| env::var("SUDO_PASSWORD").ok())
            .or_else(|| Some("Btf1_Mk3".to_string()));
        let admin_password = env::var("ASTRAL_ADMIN_PASS")
            .ok()
            .or_else(|| env::var("ADMIN_PASSWORD").ok())
            .or_else(|| Some("Copa@@2026".to_string()));
        let web_dist_path = env::var("ASTRAL_WEB_DIST").unwrap_or_else(|_| "./web/dist".to_string());
        let audit = Arc::new(AuditTrail::new(500));
        let auth_secret = crate::auth::get_auth_secret();

        Self {
            bind_addr,
            sudo_password,
            admin_password,
            web_dist_path,
            audit,
            auth_secret,
        }
    }
}
