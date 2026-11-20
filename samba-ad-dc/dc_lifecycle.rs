// ==============================================================================
// Astral AD & Hybrid DNS - Domain Controller Lifecycle Management (Rust)
// ==============================================================================

use std::process::Command;
use serde_json::Value;

pub fn demote_dc(request: &Value) -> Result<Vec<String>, String> {
    let mut steps = Vec::new();
    let admin_pass = request["admin_password"].as_str().unwrap_or("");
    let mut cmd = Command::new("samba-tool");
    cmd.args(["domain", "demote"]);
    if !admin_pass.is_empty() {
        cmd.arg(format!("--adminpass={}", admin_pass));
    }
    let output = cmd.output().map_err(|e| format!("Falha ao despromover DC: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    steps.push("Controlador de domínio despromovido com sucesso via samba-tool domain demote.".to_string());
    Ok(steps)
}
