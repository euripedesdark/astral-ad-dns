use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::AppConfig;
use crate::system::run_cmd_dry;
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
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub async fn get_drs_status(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<DrsReplicationStatus>> {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool drs showrepl", sudo, false);

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
        message: "Status de replicação DRS verificado".to_string(),
        data: Some(DrsReplicationStatus {
            raw_output: res.stdout,
            dsa_guid,
            invocation_id,
            inbound_neighbors_count: inbound_count,
            outbound_neighbors_count: outbound_count,
            has_errors,
        }),
        dry_run: false,
        correlation_id: None,
    })
}

pub async fn run_dbcheck(
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<DbCheckRequest>,
) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let d = payload.dry_run;
    let cmd = if payload.fix.unwrap_or(false) {
        "samba-tool dbcheck --cross-ncs --fix --yes"
    } else {
        "samba-tool dbcheck --cross-ncs"
    };

    let res = run_cmd_dry(cmd, sudo, d);
    let evt_id = config.audit.record(
        "admin",
        None,
        "HEALTH_DBCHECK",
        "samba:dbcheck",
        d,
        res.success,
        &format!("Verificação de integridade da base LDB (fix={:?})", payload.fix.unwrap_or(false)),
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if d {
                "[SIMULAÇÃO] Simulação do comando dbcheck realizada".to_string()
            } else if res.success {
                "Verificação da base de dados concluída sem erros estruturais".to_string()
            } else {
                "A base de dados reportou itens que necessitam de atenção".to_string()
            },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
            dry_run: d,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn run_sysvolcheck(State(config): State<Arc<AppConfig>>) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool ntacl sysvolcheck", sudo, false);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "ACLs do SYSVOL consistentes".to_string() } else { "Inconsistência de ACLs detectada no SYSVOL".to_string() },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
            dry_run: false,
            correlation_id: None,
        }),
    )
}

pub async fn run_sysvolreset(State(config): State<Arc<AppConfig>>) -> (StatusCode, Json<ApiResponse<HealthCommandResult>>) {
    let sudo = config.sudo_password.as_deref();
    let res = run_cmd_dry("samba-tool ntacl sysvolreset", sudo, false);

    let evt_id = config.audit.record(
        "admin",
        None,
        "SYSVOL_RESET",
        "samba:sysvol",
        false,
        res.success,
        "Restauração das ACLs padrão no volume SYSVOL",
    );

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: res.success,
            message: if res.success { "ACLs do SYSVOL restauradas com sucesso".to_string() } else { "Falha ao restaurar ACLs do SYSVOL".to_string() },
            data: Some(HealthCommandResult {
                success: res.success,
                stdout: res.stdout,
                stderr: res.stderr,
            }),
            dry_run: false,
            correlation_id: Some(evt_id),
        }),
    )
}

pub async fn get_powershell_sync_script(State(config): State<Arc<AppConfig>>) -> Json<ApiResponse<String>> {
    let realm = config.admin_password.as_deref().unwrap_or("SRVCLOUD.CLOUD");
    let script = format!(r#"# ==============================================================================
# Samba AD DC to Windows Server DC2 SYSVOL Replication Script
# Baseado na Arquitetura Euripedes Batista - Samba 4 AD Hardened (Part 18.9)
# ==============================================================================
param(
    [string]$PrimaryDC = "dc-erp.srvcloud.cloud",
    [string]$Domain = "{}",
    [string]$LocalSysvol = "C:\Windows\SYSVOL\sysvol"
)

$ErrorActionPreference = "Stop"
$LogPath = "C:\Scripts\Logs\sysvol_sync.log"

function Write-Log {{
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host "$Timestamp - $Message"
}}

try {{
    Write-Log "Iniciando sincronismo SYSVOL a partir de $PrimaryDC..."
    $Source = "\\$PrimaryDC\sysvol\$Domain"
    $Destination = "$LocalSysvol\$Domain"

    if (-not (Test-Path $Destination)) {{
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }}

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

    if ($ExitCode -le 7) {{
        Write-Log "Sincronismo SYSVOL concluído com sucesso (Código $ExitCode)."
    }} else {{
        Write-Log "Robocopy reportou avisos ou inconsistências (Código $ExitCode)."
    }}
}} catch {{
    Write-Log "ERRO CRÍTICO durante sincronização SYSVOL: $_"
}}
"#, realm);

    Json(ApiResponse {
        success: true,
        message: "Script PowerShell de sincronismo SYSVOL gerado com sucesso".to_string(),
        data: Some(script),
        dry_run: false,
        correlation_id: None,
    })
}
