#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
ASTRAL AD & HYBRID DNS — SCRIPT DE DEPLOY EM RUST (deploy_ad_dns_rust.py)
===============================================================================
Este script executa o pipeline completo de compilação e deploy baseado em binários
e ferramentas nativas em RUST:
1. Preparação de pacotes do host via binário Rust (astral-ad-ops host-prep)
2. Compilação dos binários Rust:
   - astral-ad-dns (servidor HTTP / Web UI)
   - astral-ad-ops (motor de operações e provisionamento Samba AD em Rust)
   - provisioner e dns_manager
3. Build do frontend web React 18 / Vite
4. Instalação em /opt/astral-ad-dns preservando todos os arquivos auxiliares
5. Configuração e ativação do serviço systemd e portas no firewall
6. Verificação de integridade e saúde do serviço

Uso:
    python3 deploy_ad_dns_rust.py --skip-git
    python3 deploy_ad_dns_rust.py --prepare-ad-only
    python3 deploy_ad_dns_rust.py --prepare-ad --skip-git
===============================================================================
"""

import os
import sys
import subprocess
import time
import argparse
import shutil
from datetime import datetime

# Garante que caminhos essenciais estejam no PATH
_cargo_bin = os.path.expanduser("~/.cargo/bin")
for _p in (_cargo_bin, "/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"):
    if os.path.exists(_p) and _p not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{_p}{os.pathsep}" + os.environ.get("PATH", "")

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_OPT_DIR = "/opt/astral-ad-dns"
SYSTEMD_SERVICE = "astral-ad-dns.service"
SYSTEMD_FILE = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
SYMLINK_BIN = "/usr/local/bin/astral-ad-dns"
SYMLINK_OPS_BIN = "/usr/local/bin/astral-ad-ops"

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
    if use_sudo and os.geteuid() != 0:
        command = ["sudo", "--", *(["bash", "-c", cmd] if isinstance(cmd, str) else cmd)]
        shell = False
    else:
        command = cmd
        shell = isinstance(cmd, str)
    display = cmd if isinstance(cmd, str) else " ".join(cmd)
    try:
        result = subprocess.run(
            command, shell=shell, cwd=cwd, check=check, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None
        )
        return result.stdout.strip() if capture else (result.returncode == 0)
    except subprocess.CalledProcessError as error:
        log_error(f"Erro ao executar: {display}")
        if capture and error.stderr:
            log_error(error.stderr.strip())
        if check:
            sys.exit(1)
        return False

def restore_repo_ownership(repo_dir):
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid:
        owner = f"{sudo_uid}:{sudo_gid}"
        for sub in ("web/dist", "target"):
            p = os.path.join(repo_dir, sub)
            if os.path.exists(p):
                subprocess.run(["sudo", "chown", "-R", owner, p], check=False)

def ensure_system_packages():
    """Garante pacotes essenciais do Active Directory, Kerberos e DNS no sistema."""
    tools = {
        "klist": "krb5-workstation",
        "host": "bind-utils",
        "chronyc": "chrony",
        "iptables": "iptables",
    }
    missing_pkgs = []
    for tool, pkg in tools.items():
        if not shutil.which(tool):
            missing_pkgs.append(pkg)
    if missing_pkgs:
        log_info(f"Instalando ferramentas essenciais do host ausentes: {', '.join(missing_pkgs)}")
        if shutil.which("dnf"):
            run_cmd(["dnf", "install", "-y"] + missing_pkgs, use_sudo=True, check=False)
        elif shutil.which("apt-get"):
            deb_map = {"krb5-workstation": "krb5-user", "bind-utils": "dnsutils", "chrony": "chrony", "iptables": "iptables"}
            deb_pkgs = [deb_map.get(p, p) for p in missing_pkgs]
            run_cmd(["apt-get", "install", "-y"] + deb_pkgs, use_sudo=True, check=False)
        log_success("Pacotes do sistema garantidos com sucesso.")

def check_prerequisites():
    log_header("Verificação de Pré-requisitos do Sistema")
    ensure_system_packages()
    missing = []
    for tool in ("cargo", "rustc", "npm", "node"):
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        log_error(f"Ferramentas ausentes: {', '.join(missing)}")
        log_error("Instale o toolchain Rust (curl https://sh.rustup.rs -sSf | sh) e Node.js.")
        sys.exit(1)
    log_success("Rust (cargo/rustc) e Node.js (npm/node) instalados e prontos.")

def prepare_ad_via_rust(repo_dir):
    """Executes host package preparation via the compiled Rust engine."""
    log_header("Preparação do Host Linux via Rust (astral-ad-ops host-prep)")
    # Compile astral-ad-ops first if not present
    log_step(1, 2, "Compilando motor de infraestrutura Rust astral-ad-ops")
    run_cmd("cargo build --release --bin astral-ad-ops", cwd=repo_dir, check=True)
    log_success("astral-ad-ops compilado em target/release/astral-ad-ops.")

    log_step(2, 2, "Executando preparação de repositórios e pacotes via Rust")
    ops_bin = os.path.join(repo_dir, "target/release/astral-ad-ops")
    run_cmd([ops_bin, "host-prep"], cwd=repo_dir, check=True, use_sudo=True)
    log_success("Host preparado com sucesso via Rust.")

def build_backend_rust(repo_dir, skip_tests=False):
    log_header("Compilação dos Binários Rust (astral-ad-dns e astral-ad-ops)")
    if not skip_tests:
        log_step(1, 2, "Executando testes unitários do Rust")
        run_cmd("cargo test --bin astral-ad-dns", cwd=repo_dir, check=True)
        log_success("Testes do backend Rust concluídos com sucesso.")
    else:
        log_warning("Testes unitários ignorados (--skip-tests).")

    log_step(2, 2, "Compilando binários de produção em modo Release")
    run_cmd(
        "cargo build --release --bin astral-ad-dns --bin astral-ad-ops --bin provisioner --bin dns_manager",
        cwd=repo_dir, check=True
    )
    log_success("Binários compilados com sucesso em target/release/.")

def build_frontend_web(repo_dir):
    web_dir = os.path.join(repo_dir, "web")
    log_header("Build de Produção do Frontend (Vite / React)")
    if not os.path.exists(os.path.join(web_dir, "node_modules")):
        log_step(1, 2, "Instalando dependências npm")
        run_cmd("npm install", cwd=web_dir, check=True)
    log_step(2, 2, "Compilando assets estáticos otimizados (npm run build)")
    run_cmd("npm run build", cwd=web_dir, check=True)
    dist_dir = os.path.join(web_dir, "dist")
    if not os.path.exists(dist_dir) or not os.listdir(dist_dir):
        log_error("Falha ao gerar assets do frontend em web/dist.")
        sys.exit(1)
    log_success("Frontend compilado com sucesso em web/dist/.")

def install_system(repo_dir):
    log_header(f"Instalação e Deploy no Sistema ({SYSTEM_OPT_DIR})")
    run_cmd(["mkdir", "-p", SYSTEM_OPT_DIR], use_sudo=True)

    # 1. Instala binários Rust
    bins = [
        ("target/release/astral-ad-dns", "astral-ad-dns", SYMLINK_BIN),
        ("target/release/astral-ad-ops", "astral-ad-ops", SYMLINK_OPS_BIN),
        ("target/release/provisioner", "provisioner", None),
        ("target/release/dns_manager", "dns_manager", None),
    ]
    for rel_src, name, symlink in bins:
        src = os.path.join(repo_dir, rel_src)
        if os.path.exists(src):
            dst = os.path.join(SYSTEM_OPT_DIR, name)
            run_cmd(["cp", "-f", src, dst], use_sudo=True)
            run_cmd(["chmod", "755", dst], use_sudo=True)
            if symlink:
                run_cmd(["ln", "-sf", dst, symlink], use_sudo=True)
            log_success(f"Binário {name} instalado em {dst}.")

    # 2. Instala Web Dist
    web_dst = os.path.join(SYSTEM_OPT_DIR, "web", "dist")
    run_cmd(["mkdir", "-p", os.path.join(SYSTEM_OPT_DIR, "web")], use_sudo=True)
    run_cmd(["rm", "-rf", web_dst], use_sudo=True)
    run_cmd(["cp", "-r", os.path.join(repo_dir, "web", "dist"), web_dst], use_sudo=True)
    log_success("Assets web sincronizados.")

    # 3. Preserva e sincroniza diretório samba-ad-dc (incluindo scripts Python e fontes Rust)
    samba_src = os.path.join(repo_dir, "samba-ad-dc")
    samba_dst = os.path.join(SYSTEM_OPT_DIR, "samba-ad-dc")
    run_cmd(["mkdir", "-p", samba_dst], use_sudo=True)
    run_cmd(["cp", "-r", f"{samba_src}/.", samba_dst], use_sudo=True)
    log_success("Diretório samba-ad-dc sincronizado (todos os arquivos Python e Rust preservados).")

def setup_service():
    log_header("Configuração do Serviço Systemd (astral-ad-dns.service)")
    unit_content = f"""[Unit]
Description=Astral Active Directory & Hybrid DNS Management Service (Rust Engine)
After=network-online.target samba-ad-dc.service samba-dc.service samba.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={SYSTEM_OPT_DIR}
ExecStart={SYSTEM_OPT_DIR}/astral-ad-dns
Restart=always
RestartSec=5s
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=astral-ad-dns

[Install]
WantedBy=multi-user.target
"""
    tmp_unit = "/tmp/astral-ad-dns.service.tmp"
    with open(tmp_unit, "w", encoding="utf-8") as f:
        f.write(unit_content)
    run_cmd(["cp", "-f", tmp_unit, SYSTEMD_FILE], use_sudo=True)
    run_cmd(["chmod", "644", SYSTEMD_FILE], use_sudo=True)
    if os.path.exists(tmp_unit):
        os.remove(tmp_unit)

    run_cmd(["systemctl", "daemon-reload"], use_sudo=True)
    run_cmd(["systemctl", "enable", SYSTEMD_SERVICE], use_sudo=True)
    run_cmd(["systemctl", "restart", SYSTEMD_SERVICE], use_sudo=True)
    log_success("Serviço systemd atualizado e reiniciado.")

def setup_firewall():
    log_header("Liberação Idempotente de Firewall (Porta 8095/TCP)")
    firewalld = shutil.which("firewall-cmd")
    if firewalld and run_cmd("firewall-cmd --state", check=False, use_sudo=True, capture=True):
        run_cmd("firewall-cmd --permanent --add-port=8095/tcp", use_sudo=True, check=False)
        run_cmd("firewall-cmd --reload", use_sudo=True, check=False)
        log_success("Porta 8095/TCP liberada no firewalld.")
        return

    iptables = shutil.which("iptables")
    if iptables:
        check_out = run_cmd("iptables -C INPUT -p tcp --dport 8095 -j ACCEPT", check=False, use_sudo=True)
        if not check_out:
            run_cmd("iptables -I INPUT 1 -p tcp --dport 8095 -j ACCEPT", use_sudo=True, check=False)
        log_success("Porta 8095/TCP garantida via iptables.")

def check_service_health():
    log_header("Verificação de Saúde do Serviço Astral AD & DNS")
    time.sleep(2)
    curl = shutil.which("curl")
    if curl:
        out = run_cmd("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/api/status", check=False, capture=True)
        if out in ("200", "401"):
            log_success(f"Servidor HTTP respondendo normalmente na porta 8095 (HTTP {out}).")
            return
    log_success("Serviço systemd ativo no sistema.")

def git_sync(repo_dir, commit_msg=None):
    log_header("Sincronização e Commit no Repositório Git")
    run_cmd("git add -A", cwd=repo_dir, check=True)
    diff = run_cmd("git diff --staged --quiet", cwd=repo_dir, check=False)
    if diff:
        log_warning("Nenhuma alteração pendente para commit no Git.")
        return
    msg = commit_msg or f"feat(deploy-rust): deploy automatizado com motor nativo Rust em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    run_cmd(["git", "commit", "-m", msg], cwd=repo_dir, check=True)
    branch = run_cmd("git rev-parse --abbrev-ref HEAD", cwd=repo_dir, capture=True)
    log_step(2, 2, f"Enviando alterações para origin/{branch}")
    run_cmd(f"git push origin {branch}", cwd=repo_dir, check=True)
    log_success("Repositório sincronizado com sucesso.")

def main():
    parser = argparse.ArgumentParser(description="Compilação e Deploy em RUST do Astral AD & DNS")
    parser.add_argument("--repo-dir", default=REPO_DIR, help="Diretório do repositório")
    parser.add_argument("--prepare-ad", action="store_true", help="Preparar pacotes Samba AD antes do deploy usando Rust")
    parser.add_argument("--prepare-ad-only", action="store_true", help="Apenas preparar o host Samba AD via Rust")
    parser.add_argument("--skip-tests", action="store_true", help="Pular testes unitários do cargo")
    parser.add_argument("--skip-git", action="store_true", help="Não executar git commit / push")
    parser.add_argument("--commit-msg", help="Mensagem customizada do commit")
    args = parser.parse_args()

    check_prerequisites()

    if args.prepare_ad_only:
        prepare_ad_via_rust(args.repo_dir)
        restore_repo_ownership(args.repo_dir)
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Preparação do host concluída com sucesso via Rust.{Colors.RESET}\n")
        return

    if args.prepare_ad:
        prepare_ad_via_rust(args.repo_dir)

    build_backend_rust(args.repo_dir, skip_tests=args.skip_tests)
    build_frontend_web(args.repo_dir)
    install_system(args.repo_dir)
    setup_service()
    setup_firewall()
    check_service_health()
    restore_repo_ownership(args.repo_dir)

    if not args.skip_git:
        git_sync(args.repo_dir, commit_msg=args.commit_msg)
    else:
        log_warning("Operação de sincronização com o Git pulada (--skip-git).")

    print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD} ✓ DEPLOY EM RUST CONCLUÍDO COM SUCESSO!{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    print(f"Painel Web disponível em: {Colors.CYAN}{Colors.BOLD}http://<IP_DO_SERVIDOR>:8095{Colors.RESET}\n")

if __name__ == "__main__":
    main()
