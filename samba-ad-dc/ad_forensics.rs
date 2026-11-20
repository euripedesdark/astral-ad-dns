// ==============================================================================
// Astral AD & Hybrid DNS - Active Directory Forensics & Health Diagnostics (Rust)
// ==============================================================================

use std::collections::HashMap;
use std::process::Command;
use serde_json::Value;

pub fn execute_forensics(_request: &Value) -> Result<Value, String> {
    let mut report = HashMap::new();

    // 1. Check services
    let mut services = HashMap::new();
    for svc in &["samba-ad-dc", "samba-dc", "samba", "named", "bind9", "step-ca", "chronyd", "chrony"] {
        let output = Command::new("systemctl").args(["is-active", svc]).output();
        let status = if let Ok(res) = output {
            String::from_utf8_lossy(&res.stdout).trim().to_string()
        } else {
            "unknown".to_string()
        };
        services.insert(svc.to_string(), status);
    }
    report.insert("services".to_string(), serde_json::to_value(services).unwrap_or_default());

    // 2. Check DRS showrepl
    let drs_out = Command::new("samba-tool").args(["drs", "showrepl", "--json"]).output();
    if let Ok(res) = drs_out {
        if res.status.success() {
            if let Ok(json_val) = serde_json::from_slice::<Value>(&res.stdout) {
                report.insert("drs".to_string(), json_val);
            }
        }
    }

    // 3. Check DB Health
    let db_out = Command::new("samba-tool").args(["dbcheck"]).output();
    if let Ok(res) = db_out {
        report.insert("dbcheck_clean".to_string(), Value::Bool(res.status.success()));
        report.insert("dbcheck_output".to_string(), Value::String(String::from_utf8_lossy(&res.stdout).to_string()));
    }

    Ok(serde_json::to_value(report).unwrap_or_default())
}
