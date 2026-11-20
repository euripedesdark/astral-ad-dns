// ==============================================================================
// Astral AD & Hybrid DNS - Step CA Health and Direct Verification (Rust)
// ==============================================================================

use std::process::Command;

pub fn check_ca_health(ca_url: &str) -> bool {
    let check = Command::new("curl")
        .args(["-k", "-s", "-f", &format!("{}/health", ca_url)])
        .output();
    if let Ok(res) = check {
        res.status.success()
    } else {
        false
    }
}
