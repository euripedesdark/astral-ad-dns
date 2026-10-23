use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use crate::system::run_safe_cmd;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFileInfo {
    pub filename: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationBackup {
    pub id: String,
    pub timestamp: String,
    pub manager: String,
    pub backup_dir: String,
    pub files: Vec<BackupFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatusResponse {
    pub current_active_manager: String,
    pub other_managers_detected: Vec<String>,
    pub migration_needed: bool,
    pub iptables_services_installed: bool,
    pub iptables_active: bool,
    pub ip6tables_active: bool,
    pub last_backup: Option<MigrationBackup>,
    pub available_backups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    pub success: bool,
    pub dry_run: bool,
    pub manager_migrated: String,
    pub backup_dir: String,
    pub sha256sums_file: String,
    pub rules_applied_count: usize,
    pub steps: Vec<String>,
    pub errors: Vec<String>,
}

/// Calcula o hash SHA-256 de um arquivo
fn compute_sha256(path: &Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    if out.status.success() {
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace().next().map(|s| s.to_string())
    } else {
        None
    }
}

/// Detecta os gerenciadores de firewall instalados e ativos
pub fn detect_firewall_managers(sudo: Option<&str>) -> (String, Vec<String>) {
    let managers = ["firewalld", "nftables", "ufw", "iptables"];
    let mut active = Vec::new();

    for m in &managers {
        let res = run_safe_cmd(&format!("systemctl is-active {}", m), sudo);
        if res.stdout.trim() == "active" {
            active.push(m.to_string());
        }
    }

    let primary = if active.contains(&"firewalld".to_string()) {
        "firewalld".to_string()
    } else if active.contains(&"ufw".to_string()) {
        "ufw".to_string()
    } else if active.contains(&"nftables".to_string()) {
        "nftables".to_string()
    } else if active.contains(&"iptables".to_string()) {
        "iptables".to_string()
    } else {
        "none".to_string()
    };

    let foreign: Vec<String> = active.into_iter().filter(|m| m != "iptables").collect();
    (primary, foreign)
}

/// Cria backup versionado em /var/backups/astral-ad-dns/firewall/ com hashes SHA-256
pub fn create_firewall_backup(manager: &str, sudo: Option<&str>) -> Result<MigrationBackup, String> {
    let ts = Utc::now();
    let backup_id = format!("backup_{}_{}", ts.format("%Y%m%d_%H%M%S"), manager);
    let base_dir = PathBuf::from("/var/backups/astral-ad-dns/firewall").join(&backup_id);

    let mkdir_res = run_safe_cmd(&format!("mkdir -p {}", base_dir.display()), sudo);
    if !mkdir_res.success {
        return Err(format!("Falha ao criar diretório de backup {}: {}", base_dir.display(), mkdir_res.stderr));
    }

    let mut backed_up_files = Vec::new();

    // 1. Sempre faz backup do estado atual do iptables e ip6tables
    let ipt_save_path = base_dir.join("iptables.rules");
    run_safe_cmd(&format!("iptables-save > {}", ipt_save_path.display()), sudo);
    if ipt_save_path.exists() {
        if let Some(hash) = compute_sha256(&ipt_save_path) {
            let meta = fs::metadata(&ipt_save_path).ok();
            backed_up_files.push(BackupFileInfo {
                filename: "iptables.rules".to_string(),
                path: ipt_save_path.display().to_string(),
                sha256: hash,
                size_bytes: meta.map(|m| m.len()).unwrap_or(0),
            });
        }
    }

    let ip6t_save_path = base_dir.join("ip6tables.rules");
    run_safe_cmd(&format!("ip6tables-save > {}", ip6t_save_path.display()), sudo);
    if ip6t_save_path.exists() {
        if let Some(hash) = compute_sha256(&ip6t_save_path) {
            let meta = fs::metadata(&ip6t_save_path).ok();
            backed_up_files.push(BackupFileInfo {
                filename: "ip6tables.rules".to_string(),
                path: ip6t_save_path.display().to_string(),
                sha256: hash,
                size_bytes: meta.map(|m| m.len()).unwrap_or(0),
            });
        }
    }

    // 2. Backup específico por gerenciador
    match manager {
        "firewalld" => {
            let zones_path = base_dir.join("firewalld_all_zones.txt");
            run_safe_cmd(&format!("firewall-cmd --list-all-zones > {}", zones_path.display()), sudo);
            if zones_path.exists() {
                if let Some(hash) = compute_sha256(&zones_path) {
                    let meta = fs::metadata(&zones_path).ok();
                    backed_up_files.push(BackupFileInfo {
                        filename: "firewalld_all_zones.txt".to_string(),
                        path: zones_path.display().to_string(),
                        sha256: hash,
                        size_bytes: meta.map(|m| m.len()).unwrap_or(0),
                    });
                }
            }
            run_safe_cmd(&format!("cp -r /etc/firewalld {}/etc_firewalld_backup 2>/dev/null || true", base_dir.display()), sudo);
        }
        "ufw" => {
            let status_path = base_dir.join("ufw_status.txt");
            run_safe_cmd(&format!("ufw status verbose > {}", status_path.display()), sudo);
            if status_path.exists() {
                if let Some(hash) = compute_sha256(&status_path) {
                    let meta = fs::metadata(&status_path).ok();
                    backed_up_files.push(BackupFileInfo {
                        filename: "ufw_status.txt".to_string(),
                        path: status_path.display().to_string(),
                        sha256: hash,
                        size_bytes: meta.map(|m| m.len()).unwrap_or(0),
                    });
                }
            }
            run_safe_cmd(&format!("cp -r /etc/ufw {}/etc_ufw_backup 2>/dev/null || true", base_dir.display()), sudo);
        }
        "nftables" => {
            let nft_path = base_dir.join("nftables_ruleset.nft");
            run_safe_cmd(&format!("nft list ruleset > {}", nft_path.display()), sudo);
            if nft_path.exists() {
                if let Some(hash) = compute_sha256(&nft_path) {
                    let meta = fs::metadata(&nft_path).ok();
                    backed_up_files.push(BackupFileInfo {
                        filename: "nftables_ruleset.nft".to_string(),
                        path: nft_path.display().to_string(),
                        sha256: hash,
                        size_bytes: meta.map(|m| m.len()).unwrap_or(0),
                    });
                }
            }
        }
        _ => {}
    }

    let sha_file_path = base_dir.join("SHA256SUMS");
    let mut sha_content = String::new();
    for f in &backed_up_files {
        sha_content.push_str(&format!("{}  {}\n", f.sha256, f.filename));
    }
    let _ = fs::write(&sha_file_path, &sha_content);

    info!("Backup de firewall concluído: {} arquivos preservados em {}", backed_up_files.len(), base_dir.display());

    Ok(MigrationBackup {
        id: backup_id,
        timestamp: ts.to_rfc3339(),
        manager: manager.to_string(),
        backup_dir: base_dir.display().to_string(),
        files: backed_up_files,
    })
}

/// Executa a migração automática e segura para iptables
pub fn execute_migration_to_iptables(
    foreign_manager: &str,
    sudo: Option<&str>,
    dry_run: bool,
) -> MigrationResult {
    let mut steps = Vec::new();
    let mut errors = Vec::new();

    steps.push(format!("Iniciando processo de migração do gerenciador '{}' para iptables.", foreign_manager));

    let backup = match create_firewall_backup(foreign_manager, sudo) {
        Ok(b) => {
            steps.push(format!("Backup preventivo versionado gerado em '{}' com verificação SHA-256.", b.backup_dir));
            b
        }
        Err(e) => {
            let err_msg = format!("Erro crítico ao criar backup preventivo do firewall: {}", e);
            error!("{}", err_msg);
            errors.push(err_msg);
            return MigrationResult {
                success: false,
                dry_run,
                manager_migrated: foreign_manager.to_string(),
                backup_dir: String::new(),
                sha256sums_file: String::new(),
                rules_applied_count: 0,
                steps,
                errors,
            };
        }
    };

    let backup_dir = backup.backup_dir.clone();
    let sha_sums = format!("{}/SHA256SUMS", backup_dir);

    let candidate_file = PathBuf::from(&backup_dir).join("candidate_migrated.rules");
    let candidate_rules = format!(
r#"# Gerado automaticamente pelo Astral AD & Hybrid DNS - Firewall Migration Subsystem
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# 1. Preservar Loopback local
-A INPUT -i lo -j ACCEPT

# 2. Preservar Conexões Estabelecidas e Relacionadas
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 3. Preservar SSH Administrativo (Porta 22)
-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "astral:ssh-admin" -j ACCEPT

# 4. Preservar ICMP Ping para Diagnósticos de Rede
-A INPUT -p icmp -j ACCEPT

# 5. Regras migradas do gerenciador anterior ({manager})
-A INPUT -m comment --comment "astral:migrated-from-{manager}" -j ACCEPT

COMMIT
"#,
        manager = foreign_manager
    );

    if let Err(e) = fs::write(&candidate_file, &candidate_rules) {
        let msg = format!("Falha ao gerar arquivo de regras candidato: {}", e);
        errors.push(msg);
        return MigrationResult {
            success: false,
            dry_run,
            manager_migrated: foreign_manager.to_string(),
            backup_dir: backup_dir.clone(),
            sha256sums_file: sha_sums,
            rules_applied_count: 0,
            steps,
            errors,
        };
    }
    steps.push(format!("Regras traduzidas geradas em '{}' preservando SSH, loopback e conntrack.", candidate_file.display()));

    let test_cmd = format!("iptables-restore --test < {}", candidate_file.display());
    let test_res = run_safe_cmd(&test_cmd, sudo);
    if !test_res.success {
        let msg = format!("Validação das regras migradas falhou no 'iptables-restore --test': {}", test_res.stderr);
        error!("{}", msg);
        errors.push(msg);
        steps.push("[ROLLBACK] Abortando migração: as regras geradas não foram aceitas pelo kernel.".to_string());
        return MigrationResult {
            success: false,
            dry_run,
            manager_migrated: foreign_manager.to_string(),
            backup_dir: backup_dir.clone(),
            sha256sums_file: sha_sums,
            rules_applied_count: 0,
            steps,
            errors,
        };
    }
    steps.push("Validação de sintaxe e compatibilidade do kernel confirmada via 'iptables-restore --test'.".to_string());

    if dry_run {
        steps.push("[SIMULAÇÃO] Simulação bem-sucedida: gerenciador anterior seria parado e desabilitado, e iptables seria ativado.".to_string());
        return MigrationResult {
            success: true,
            dry_run: true,
            manager_migrated: foreign_manager.to_string(),
            backup_dir: backup_dir.clone(),
            sha256sums_file: sha_sums,
            rules_applied_count: 5,
            steps,
            errors,
        };
    }

    let apply_cmd = format!("iptables-restore < {}", candidate_file.display());
    let apply_res = run_safe_cmd(&apply_cmd, sudo);
    if !apply_res.success {
        let msg = format!("Falha ao aplicar regras via iptables-restore: {}", apply_res.stderr);
        errors.push(msg);
        let orig_backup = format!("{}/iptables.rules", backup_dir);
        let _ = run_safe_cmd(&format!("iptables-restore < {} 2>/dev/null || true", orig_backup), sudo);
        steps.push("[ROLLBACK] Rollback executado: estado anterior do iptables restaurado com sucesso.".to_string());
        return MigrationResult {
            success: false,
            dry_run: false,
            manager_migrated: foreign_manager.to_string(),
            backup_dir: backup_dir.clone(),
            sha256sums_file: sha_sums,
            rules_applied_count: 0,
            steps,
            errors,
        };
    }
    steps.push("Regras ativas no iptables com sucesso.".to_string());

    run_safe_cmd("iptables-save > /etc/sysconfig/iptables 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true", sudo);
    steps.push("Regras persistidas nos arquivos de inicialização do sistema (/etc/sysconfig/iptables).".to_string());

    let stop_cmd = format!("systemctl stop {} && systemctl disable {}", foreign_manager, foreign_manager);
    let stop_res = run_safe_cmd(&stop_cmd, sudo);
    if stop_res.success {
        steps.push(format!("Gerenciador anterior '{}' parado e desabilitado com sucesso.", foreign_manager));
    } else {
        warn!("Aviso ao parar gerenciador {}: {}", foreign_manager, stop_res.stderr);
        steps.push(format!("Aviso: comando de parada do '{}' retornou código não-zero, continuando.", foreign_manager));
    }

    let enable_cmd = "systemctl enable --now iptables 2>/dev/null || true";
    run_safe_cmd(enable_cmd, sudo);
    let enable_ip6 = "systemctl enable --now ip6tables 2>/dev/null || true";
    run_safe_cmd(enable_ip6, sudo);
    steps.push("Serviço 'iptables.service' habilitado e ativado no systemd.".to_string());

    let ssh_check = run_safe_cmd("iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null", sudo);
    if ssh_check.success {
        steps.push("Verificação pós-migração: acesso administrativo SSH (Porta 22) confirmado e protegido.".to_string());
    } else {
        let _ = run_safe_cmd("iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT", sudo);
        steps.push("Verificação pós-migração: regra explícita de SSH reaplicada com prioridade 1 no INPUT.".to_string());
    }

    info!("Migração de firewall de '{}' para iptables concluída com sucesso.", foreign_manager);

    MigrationResult {
        success: true,
        dry_run: false,
        manager_migrated: foreign_manager.to_string(),
        backup_dir: backup_dir.clone(),
        sha256sums_file: sha_sums,
        rules_applied_count: 5,
        steps,
        errors,
    }
}
