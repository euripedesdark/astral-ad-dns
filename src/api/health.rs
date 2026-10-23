use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::run_safe_cmd;
use crate::api::users::ApiResponse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DrsReplicationStatus {
    pub raw_output: String,
    pub dsa_guid: String,
    pub invocation_id: String,
    pub inbound_neighbors_count: usize,
    pub outbound_neighbors_count: usize,
    pub has_errors: bool,
}

#[derive(Deserialize, Debug)]
pub struct DbCheckRequest {
    pub fix: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub async fn get_drs_status(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<DrsReplicationStatus>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool drs showrepl", sudo);

    let mut dsa_guid = String::new();
    let mut invocation_id = String::new();
    let mut inbound_count = 0;
    let mut outbound_count = 0;
    let mut current_section = "";

    for line in res.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("DSA object GUID:") {
            if let Some((_, v)) = trimmed.split_once(':') {
                dsa_guid = v.trim().to_string();
            }
        } else if trimmed.starts_with("DSA invocationId:") {
            if let Some((_, v)) = trimmed.split_once(':') {
                invocation_id = v.trim().to_string();
            }
        } else if trimmed.contains("==== INBOUND NEIGHBORS ====") {
            current_section = "inbound";
        } else if trimmed.contains("==== OUTBOUND NEIGHBORS ====") {
            current_section = "outbound";
        } else if trimmed.contains("==== KCC CONNECTION OBJECTS ====") {
            current_section = "kcc";
        } else if trimmed.starts_with("DC=") || trimmed.starts_with("CN=") {
            if current_section == "inbound" {
                inbound_count += 1;
            } else if current_section == "outbound" {
                outbound_count += 1;
            }
        }
    }

    let has_errors = res.stdout.contains("failed") || res.stdout.contains("error") || !res.success;

    Json(ApiResponse {
        success: true,
        message: "DRS replication status checked".to_string(),
        data: Some(DrsReplicationStatus {
            raw_output: res.stdout,
            dsa_guid,
            invocation_id,
            inbound_neighbors_count: inbound_count,
            outbound_neighbors_count: outbound_count,
            has_errors,
        }),
    })
}

pub async fn run_dbcheck(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<DbCheckRequest>,
) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let cmd = if payload.fix.unwrap_or(false) {
        "samba-tool dbcheck --cross-ncs --fix --yes"
    } else {
        "samba-tool dbcheck --cross-ncs"
    };

    let res = run_safe_cmd(cmd, sudo);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "Database check passed".to_string() } else { "Database check reported issues".to_string() },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
        }),
    )
}

pub async fn run_sysvolcheck(State(config): State<Arc<AppConfig>>) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool ntacl sysvolcheck", sudo);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "SYSVOL ACLs are consistent".to_string() } else { "SYSVOL ACL mismatch detected".to_string() },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
        }),
    )
}

pub async fn run_sysvolreset(State(config): State<Arc<AppConfig>>) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let res = run_safe_cmd("samba-tool ntacl sysvolreset", sudo);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "SYSVOL ACLs reset successfully".to_string() } else { "Failed to reset SYSVOL ACLs".to_string() },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
        }),
    )
}

pub async fn get_powershell_sync_script(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<String>> {
    let _realm = config.admin_password.as_deref().unwrap_or("SRVCLOUD.CLOUD");
    // Article Part 18.9 script
    let script = r#"# ==============================================================================
# Samba AD DC to Windows Server DC2 SYSVOL Replication Script
# Based on Euripedes Batista's Samba 4 AD Hardened Architecture Guide (Part 18.9)
# ==============================================================================
param(
    [string]$PrimaryDC = "dc-erp.srvcloud.cloud",
    [string]$Domain = "srvcloud.cloud",
    [string]$LocalSysvol = "C:\Windows\SYSVOL\sysvol"
)

$ErrorActionPreference = "Stop"
$LogPath = "C:\Scripts\Logs\sysvol_sync.log"

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host "$Timestamp - $Message"
}

try {
    Write-Log "Starting SYSVOL pull synchronization from $PrimaryDC..."
    $Source = "\\$PrimaryDC\sysvol\$Domain"
    $Destination = "$LocalSysvol\$Domain"

    if (-not (Test-Path $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    # Robocopy options: Mirror, Copy Data/Attributes/Timestamps/Security, 3 retries
    $RobocopyArgs = @(
        $Source,
        $Destination,
        "/MIR",
        "/COPY:DATSO",
        "/R:3",
        "/W:5",
        "/NP",
        "/NFL",
        "/NDL"
    )

    & robocopy.exe @RobocopyArgs
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -le 7) {
        Write-Log "SYSVOL sync completed successfully with code $ExitCode."
    } else {
        Write-Log "Robocopy reported warnings or errors (Code $ExitCode)."
    }
} catch {
    Write-Log "FATAL ERROR during SYSVOL sync: $_"
}
"#;

    Json(ApiResponse {
        success: true,
        message: "Generated PowerShell SYSVOL sync script".to_string(),
        data: Some(script.to_string()),
    })
}
