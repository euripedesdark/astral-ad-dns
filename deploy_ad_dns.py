#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
ASTRAL AD & HYBRID DNS — SCRIPT DE BUILD, DEPLOY NO SISTEMA E SYNC GIT
===============================================================================
Este script executa o pipeline completo:
1. Compilação do backend Rust em modo Release (com verificação de testes)
2. Build de produção do frontend React 18 / Vite
3. Cópia do binário e estáticos para o diretório de sistema (/opt/astral-ad-dns)
4. Configuração e inicialização da unidade systemd a partir do diretório de sistema
5. Verificação da saúde do serviço (HTTP 200 na porta 8095)
6. Commit e Push automático de todas as alterações para o Git

Uso:
    python3 deploy_ad_dns.py
    python3 deploy_ad_dns.py --skip-tests
    python3 deploy_ad_dns.py --skip-git
    python3 deploy_ad_dns.py --help
===============================================================================
"""

import os
import sys
import subprocess
import time
import argparse
import shutil
from datetime import datetime

# Configurações Padrão
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_OPT_DIR = "/opt/astral-ad-dns"
SYSTEMD_SERVICE = "astral-ad-dns.service"
SYSTEMD_FILE = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
SYMLINK_BIN = "/usr/local/bin/astral-ad-dns"
SUDO_PASS = os.environ.get("ASTRAL_SUDO_PASS", "Btf1_Mk3")

class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

def log_header(msg):
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD} {msg}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'='*70}{Colors.RESET}\n")

def log_step(step_num, total_steps, title):
    print(f"{Colors.BOLD}[{step_num}/{total_steps}]{Colors.RESET} {Colors.CYAN}{title}...{Colors.RESET}")

def log_success(msg):
    print(f"  {Colors.GREEN}✓ {msg}{Colors.RESET}")

def log_warning(msg):
    print(f"  {Colors.YELLOW}⚠ {msg}{Colors.RESET}")

def log_error(msg):
    print(f"  {Colors.RED}✗ {msg}{Colors.RESET}")

def run_cmd(cmd, cwd=None, check=True, use_sudo=False, capture=False):
    """Executa um comando local ou com sudo encapsulado via bash -c."""
    if use_sudo and os.geteuid() != 0:
        if isinstance(cmd, list):
            cmd_str = subprocess.list2cmdline(cmd)
        else:
            cmd_str = cmd
        escaped_cmd = cmd_str.replace("'", "'\\''")
        final_cmd = f"echo '{SUDO_PASS}' | sudo -S bash -c '{escaped_cmd}'"
        is_shell = True
    else:
        if isinstance(cmd, list):
            final_cmd = cmd
            is_shell = False
        else:
            final_cmd = cmd
            is_shell = True

    cmd_display = cmd if isinstance(cmd, str) else " ".join(cmd)
    try:
        if capture:
            res = subprocess.run(
                final_cmd,
                shell=is_shell,
                cwd=cwd,
                check=check,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return res.stdout.strip()
        else:
            subprocess.run(
                final_cmd,
                shell=is_shell,
                cwd=cwd,
                check=check,
                text=True
            )
            return True
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao executar: {cmd_display}")
        if capture and e.stderr:
            print(f"{Colors.RED}{e.stderr.strip()}{Colors.RESET}")
        if check:
            sys.exit(1)
        return False

def check_prerequisites():
    """Verifica se ferramentas essenciais estão disponíveis."""
    for tool in ["cargo", "rustc", "npm", "node", "git"]:
        if not shutil.which(tool):
            log_error(f"Ferramenta obrigatória não encontrada no PATH: {tool}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Compilação, Deploy em Sistema e Sync Git do Astral AD & DNS")
    parser.add_argument("--repo-dir", default=REPO_DIR, help="Diretório raiz do repositório astral-ad-dns")
    parser.add_argument("--skip-tests", action="store_true", help="Pular execução de testes unitários do cargo")
    parser.add_argument("--skip-git", action="store_true", help="Pular commit e push para o repositório Git")
    parser.add_argument("--commit-msg", help="Mensagem customizada para o commit no Git")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    web_dir = os.path.join(repo_dir, "web")
    target_bin = os.path.join(repo_dir, "target", "release", "astral-ad-dns")

    if not os.path.exists(os.path.join(repo_dir, "Cargo.toml")):
        log_error(f"Diretório inválido! Cargo.toml não encontrado em: {repo_dir}")
        sys.exit(1)

    start_time = time.time()
    total_steps = 5 if args.skip_git else 6
    current_step = 1

    log_header("ASTRAL AD & HYBRID DNS — PIPELINE DE BUILD & DEPLOY")
    print(f"  • Repositório Origem: {Colors.BOLD}{repo_dir}{Colors.RESET}")
    print(f"  • Destino de Sistema: {Colors.BOLD}{SYSTEM_OPT_DIR}{Colors.RESET}")
    print(f"  • Serviço Systemd   : {Colors.BOLD}{SYSTEMD_SERVICE}{Colors.RESET}")
    print(f"  • Porta Alvo        : {Colors.BOLD}8095 (HTTP / Axum REST){Colors.RESET}\n")

    check_prerequisites()

    # -------------------------------------------------------------------------
    # PASSO 1: Build do Frontend React / Vite
    # -------------------------------------------------------------------------
    log_step(current_step, total_steps, "Construindo Frontend SPA (web/)")
    current_step += 1

    if not os.path.exists(os.path.join(web_dir, "node_modules")):
        log_warning("node_modules ausente em web/. Executando npm install...")
        run_cmd(["npm", "install"], cwd=web_dir)

    run_cmd(["npm", "run", "build"], cwd=web_dir)
    dist_index = os.path.join(web_dir, "dist", "index.html")
    if not os.path.exists(dist_index):
        log_error("Falha no build do frontend! dist/index.html não foi gerado.")
        sys.exit(1)
    log_success("Frontend React 18 compilado com sucesso em web/dist/")

    # -------------------------------------------------------------------------
    # PASSO 2: Testes e Compilação do Backend Rust em Modo Release
    # -------------------------------------------------------------------------
    log_step(current_step, total_steps, "Compilando Backend Rust (Cargo Release)")
    current_step += 1

    if not args.skip_tests:
        print("  • Executando suíte de testes unitários...")
        run_cmd(["cargo", "test", "--quiet"], cwd=repo_dir)
        log_success("Todos os testes unitários passaram com sucesso!")

    print("  • Compilando binário release otimizado...")
    run_cmd(["cargo", "build", "--release"], cwd=repo_dir)

    if not os.path.exists(target_bin):
        log_error(f"Binário release não encontrado em: {target_bin}")
        sys.exit(1)

    bin_size_mb = os.path.getsize(target_bin) / (1024 * 1024)
    log_success(f"Binário release gerado com sucesso ({bin_size_mb:.2f} MB)")

    # -------------------------------------------------------------------------
    # PASSO 3: Cópia e Instalação na Pasta de Sistema (/opt/astral-ad-dns)
    # -------------------------------------------------------------------------
    log_step(current_step, total_steps, f"Copiando arquivos para diretório de sistema ({SYSTEM_OPT_DIR})")
    current_step += 1

    # Cria diretórios no /opt
    run_cmd(f"mkdir -p {SYSTEM_OPT_DIR}/web", use_sudo=True)

    # Copia binário
    system_bin = os.path.join(SYSTEM_OPT_DIR, "astral-ad-dns")
    run_cmd(f"cp -f {target_bin} {system_bin}", use_sudo=True)
    run_cmd(f"chmod 755 {system_bin}", use_sudo=True)

    # Cria symlink global
    run_cmd(f"ln -sf {system_bin} {SYMLINK_BIN}", use_sudo=True)

    # Copia bundle do frontend
    run_cmd(f"rm -rf {SYSTEM_OPT_DIR}/web/dist && cp -r {web_dir}/dist {SYSTEM_OPT_DIR}/web/dist", use_sudo=True)

    # Copia scripts de automação samba-ad-dc se existirem
    samba_scripts_dir = os.path.join(repo_dir, "samba-ad-dc")
    if os.path.exists(samba_scripts_dir):
        run_cmd(f"mkdir -p {SYSTEM_OPT_DIR}/samba-ad-dc", use_sudo=True)
        run_cmd(f"cp -rf {samba_scripts_dir}/* {SYSTEM_OPT_DIR}/samba-ad-dc/", use_sudo=True)

    # Copia scripts de automação dns se existirem
    dns_scripts_dir = os.path.join(repo_dir, "dns")
    if os.path.exists(dns_scripts_dir):
        run_cmd(f"mkdir -p {SYSTEM_OPT_DIR}/dns", use_sudo=True)
        run_cmd(f"cp -rf {dns_scripts_dir}/* {SYSTEM_OPT_DIR}/dns/", use_sudo=True)

    log_success(f"Binário e arquivos estáticos instalados em {SYSTEM_OPT_DIR}")

    # -------------------------------------------------------------------------
    # PASSO 4: Atualização da Unidade Systemd e Inicialização do Serviço
    # -------------------------------------------------------------------------
    log_step(current_step, total_steps, "Configurando e iniciando serviço no Systemd")
    current_step += 1

    unit_content = f"""[Unit]
Description=Astral Active Directory & Hybrid DNS Management Service
After=network.target samba.service named.service chronyd.service
Wants=samba.service named.service

[Service]
Type=simple
User=root
WorkingDirectory={SYSTEM_OPT_DIR}
ExecStart={system_bin}
Restart=always
RestartSec=5
Environment=ASTRAL_BIND_ADDR=0.0.0.0:8095
Environment=ASTRAL_ADMIN_PASS=Copa@@2026
Environment=ASTRAL_SUDO_PASS={SUDO_PASS}
Environment=ASTRAL_WEB_DIST={SYSTEM_OPT_DIR}/web/dist

[Install]
WantedBy=multi-user.target
"""
    temp_unit = "/tmp/astral-ad-dns.service.tmp"
    with open(temp_unit, "w") as f:
        f.write(unit_content)

    run_cmd(f"mv {temp_unit} {SYSTEMD_FILE}", use_sudo=True)
    run_cmd(f"chmod 644 {SYSTEMD_FILE}", use_sudo=True)
    run_cmd("systemctl daemon-reload", use_sudo=True)
    run_cmd(f"systemctl enable {SYSTEMD_SERVICE}", use_sudo=True)
    run_cmd(f"systemctl restart {SYSTEMD_SERVICE}", use_sudo=True)

    time.sleep(2.0)

    # -------------------------------------------------------------------------
    # PASSO 5: Verificação de Saúde e Portas em Execução
    # -------------------------------------------------------------------------
    log_step(current_step, total_steps, "Verificando integridade operacional do servidor")
    current_step += 1

    status_out = run_cmd(f"systemctl is-active {SYSTEMD_SERVICE}", capture=True)
    if status_out != "active":
        log_error(f"O serviço falhou ao iniciar! Status atual: {status_out}")
        run_cmd(f"journalctl -u {SYSTEMD_SERVICE} -n 30 --no-pager", use_sudo=True)
        sys.exit(1)

    log_success(f"Serviço {SYSTEMD_SERVICE} ativo e em execução!")

    # Teste de endpoint HTTP local
    health_check = run_cmd("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/api/auth/providers", capture=True)
    if health_check in ["200", "401"]:
        log_success(f"Endpoint HTTP 8095 respondendo com sucesso (Código HTTP: {health_check})")
    else:
        log_warning(f"Endpoint retornou código HTTP {health_check}. Verifique os logs se necessário.")

    # -------------------------------------------------------------------------
    # PASSO 6: Commit e Push para o Git
    # -------------------------------------------------------------------------
    if not args.skip_git:
        log_step(current_step, total_steps, "Sincronizando alterações com o repositório Git")
        
        # Garante adição de arquivos atualizados
        run_cmd(["git", "add", "."], cwd=repo_dir)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        commit_msg = args.commit_msg or f"feat(deploy): automated build, opt install, systemd service and git sync [{now_str}]"

        # Tenta commitar (se houver modificações)
        commit_res = run_cmd(f'git commit -m "{commit_msg}"', cwd=repo_dir, check=False, capture=True)
        if "nothing to commit" in commit_res.lower():
            log_success("Nenhuma alteração de código pendente para commit no Git.")
        else:
            log_success("Alterações commitadas localmente no Git.")

        # Obtém branch atual
        current_branch = run_cmd("git rev-parse --abbrev-ref HEAD", cwd=repo_dir, capture=True)
        print(f"  • Enviando branch '{current_branch}' para origin...")
        push_res = run_cmd(["git", "push", "origin", current_branch], cwd=repo_dir, check=False, capture=True)
        if push_res is not False:
            log_success(f"Repositório Git atualizado com sucesso em origin/{current_branch}!")
        else:
            log_warning("Aviso no push do Git (verifique autenticação ou conflitos remotos).")

    elapsed = time.time() - start_time
    log_header(f"DEPLOY CONCLUÍDO COM SUCESSO EM {elapsed:.1f} SEGUNDOS!")
    print(f"  {Colors.GREEN}{Colors.BOLD}✓ Binário e frontend servindo a partir de: {SYSTEM_OPT_DIR}{Colors.RESET}")
    print(f"  {Colors.GREEN}{Colors.BOLD}✓ URL de Acesso: http://127.0.0.1:8095 ou via painel HCI{Colors.RESET}\n")

if __name__ == "__main__":
    main()
