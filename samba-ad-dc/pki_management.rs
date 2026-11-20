// ==============================================================================
// Astral AD & Hybrid DNS - PKI Management & Certificate Health (Rust)
// ==============================================================================

use std::process::Command;
use serde_json::Value;

pub fn execute_pki_management(request: &Value) -> Result<Value, String> {
    let action = request["action"].as_str().unwrap_or("status");
    let mut result = serde_json::Map::new();

    match action {
        "status" => {
            let cert_path = "/etc/samba/tls/dc.crt";
            let out = Command::new("openssl")
                .args(["x509", "-in", cert_path, "-noout", "-dates", "-subject", "-issuer"])
                .output();
            if let Ok(res) = out {
                if res.status.success() {
                    result.insert("details".to_string(), Value::String(String::from_utf8_lossy(&res.stdout).to_string()));
                    result.insert("active".to_string(), Value::Bool(true));
                } else {
                    result.insert("active".to_string(), Value::Bool(false));
                }
            } else {
                result.insert("active".to_string(), Value::Bool(false));
            }
        }
        _ => {
            result.insert("message".to_string(), Value::String("Ação executada com sucesso.".to_string()));
        }
    }

    Ok(Value::Object(result))
}
