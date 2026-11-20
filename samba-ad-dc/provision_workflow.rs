// ==============================================================================
// Astral AD & Hybrid DNS - Provisioning Workflow Coordinator (Rust)
// ==============================================================================

use std::path::Path;
use std::process::Command;
use serde_json::Value;

use crate::provision_dc1::{execute_dc1_provision, ProvisionRequest};

pub fn execute_workflow(request_val: &Value, root: &Path) -> Result<Value, String> {
    // 1. If Python provision_workflow is present on the system, invoke it for full feature parity
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("ASTRAL_SCRIPTS_DIR") {
        candidates.push(std::path::PathBuf::from(dir).join("ad_operations.py"));
    }
    candidates.push(std::path::PathBuf::from("/opt/astral-ad-dns/samba-ad-dc/ad_operations.py"));
    candidates.push(std::path::PathBuf::from("samba-ad-dc/ad_operations.py"));

    if let Some(script) = candidates.into_iter().find(|p| p.is_file()) {
        use std::io::Write;
        use std::process::Stdio;
        if let Ok(mut child) = Command::new("python3")
            .arg(&script)
            .arg("provision")
            .arg("--request-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(request_val.to_string().as_bytes());
            }
            if let Ok(output) = child.wait_with_output() {
                let stdout_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(val) = serde_json::from_str::<Value>(stdout_str.trim()) {
                    if val["success"] == true {
                        return Ok(val["data"].clone());
                    } else if let Some(err) = val["error"].as_str() {
                        return Err(err.to_string());
                    }
                }
            }
        }
    }

    // 2. Direct native Rust provision engine
    let req: ProvisionRequest = serde_json::from_value(request_val.clone())
        .map_err(|e| format!("Formato inválido de requisição de provisionamento: {}", e))?;

    let res = execute_dc1_provision(&req, root)?;
    let val = serde_json::to_value(&res)
        .map_err(|e| format!("Falha ao serializar resposta: {}", e))?;
    Ok(val)
}
