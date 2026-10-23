#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import time
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, "auth.env")

def _parse_valor(raw):
    raw = raw.strip()
    if '"' in raw:
        return raw.split('"')[1]
    if "'" in raw:
        return raw.split("'")[1]
    return raw

def _ler_env():
    try:
        with open(ENV_FILE, 'r') as f:
            return f.read()
    except PermissionError:
        r = subprocess.run(["sudo", "cat", ENV_FILE], capture_output=True, text=True)
        if r.returncode != 0:
            print("Sem permissao para ler " + ENV_FILE)
            sys.exit(1)
        return r.stdout
    except FileNotFoundError:
        print("Arquivo " + ENV_FILE + " nao encontrado!")
        sys.exit(1)

def carregar_env():
    env = {}
    for line in _ler_env().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        env[key.strip()] = _parse_valor(value)
    obrig = ["HOSTNAME_COMPLETO", "NOME_NETBIOS", "REALM", "IP_ESTATICO", "INTERFACE_REDE", "SENHA_ADMIN", "CERT_PWD"]
    faltando = [k for k in obrig if not env.get(k)]
    if faltando:
        print("Variaveis ausentes: " + ', '.join(faltando))
        sys.exit(1)
    return env

CFG = carregar_env()
HOSTNAME_COMPLETO = CFG["HOSTNAME_COMPLETO"]
NOME_NETBIOS = CFG["NOME_NETBIOS"]
REALM = CFG["REALM"]
IP_ESTATICO = CFG["IP_ESTATICO"]
INTERFACE_REDE = CFG["INTERFACE_REDE"]
ADMIN_USER = CFG.get("ADMIN_USER") or "Administrator"
SENHA_ADMIN = CFG["SENHA_ADMIN"]
CERT_PWD = CFG["CERT_PWD"]

CERT_DIR = "/etc/samba/tls"
KEY_PATH = CERT_DIR + "/" + NOME_NETBIOS + ".key"
CERT_PATH = CERT_DIR + "/" + NOME_NETBIOS + ".crt"
STEP_CA_DIR = "/etc/step-ca"
STEP_CA_CONFIG = STEP_CA_DIR + "/config/ca.json"
STEP_CA_ROOT_CERT = STEP_CA_DIR + "/certs/root_ca.crt"
STEP_CA_PASSWORD_FILE = STEP_CA_DIR + "/password.txt"
RENEW_LOG = "/var/log/step-ca-renew.log"

CERT_SANS = [
    "DNS:" + HOSTNAME_COMPLETO,
    "DNS:" + HOSTNAME_COMPLETO.split('.')[0],
    "DNS:" + REALM.lower(),
    "DNS:ldap." + REALM.lower(),
    "DNS:_ldap._tcp.dc._msdcs." + REALM.lower(),
    "DNS:_kerberos._tcp.dc._msdcs." + REALM.lower(),
    "DNS:_gc._tcp." + REALM.lower(),
    "DNS:ca." + REALM.lower(),
    "DNS:pki." + REALM.lower(),
    "IP:" + IP_ESTATICO,
    "IP:127.0.0.1"
]

NON_INTERACTIVE = False

def run_command(command, shell=False, check=True):
    try:
        cmd_str = command if isinstance(command, str) else ' '.join(command)
        print("Executando: " + cmd_str)
        subprocess.run(command, shell=shell, check=check, text=True, stdout=sys.stdout, stderr=sys.stderr)
        print("-" * 40)
        time.sleep(1)
    except subprocess.CalledProcessError as e:
        print("ERRO ao executar comando: " + str(e))
        if check:
            raise e

def wait_for_enter(prompt="Pressione Enter para continuar..."):
    if NON_INTERACTIVE:
        print(prompt + " [Auto-Confirmado]")
        return
    input("\n" + prompt)

def create_file_with_content(filepath, content):
    print("Criando arquivo: " + filepath)
    try:
        temp_filepath = "/tmp/" + os.path.basename(filepath) + ".tmp"
        with open(temp_filepath, "w") as f:
            f.write(content)
        run_command(["sudo", "mv", temp_filepath, filepath])
        run_command(["sudo", "restorecon", filepath], check=False)
        print("Arquivo " + filepath + " criado.")
    except IOError as e:
        print("ERRO ao escrever " + filepath + ": " + str(e))
        sys.exit(1)

def update_smb_conf(params_to_add):
    print("Atualizando /etc/samba/smb.conf...")
    smb_conf_path = "/etc/samba/smb.conf"
    if not os.path.exists(smb_conf_path):
        return
    with open(smb_conf_path, 'r') as f:
        lines = f.readlines()
    param_keys = [p.split('=')[0].strip() for p in params_to_add]
    new_lines = []
    in_global = False
    global_ended = False
    inserted = False
    for line in lines:
        s = line.strip()
        if s.lower() == '[global]':
            in_global = True
            new_lines.append(line)
            continue
        elif in_global and s.startswith('['):
            in_global = False
            global_ended = True
        if in_global:
            k = s.split('=')[0].strip()
            if k in param_keys:
                continue
        if global_ended and not inserted:
            for p in params_to_add:
                new_lines.append("\t" + p + "\n")
            inserted = True
        new_lines.append(line)
    if in_global and not inserted:
        for p in params_to_add:
            new_lines.append("\t" + p + "\n")
    create_file_with_content(smb_conf_path, "".join(new_lines))

def esperar_samba_ldap(tentativas=20, intervalo=5):
    print("Aguardando Samba AD DC...")
    for i in range(1, tentativas + 1):
        try:
            r = subprocess.run(["sudo", "samba-tool", "domain", "level", "show"], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                print("  Samba ativo (tentativa " + str(i) + ").")
                return True
        except Exception:
            pass
        print("  Tentativa " + str(i) + "/" + str(tentativas))
        time.sleep(intervalo)
    print("  Samba NAO respondeu!")
    return False

def aguardar_step_ca_healthy(tentativas=30, intervalo=2):
    print("Aguardando Step-CA responder...")
    url = "https://" + IP_ESTATICO + ":8443"
    for i in range(1, tentativas + 1):
        try:
            r = subprocess.run(["curl", "-sk", "--connect-timeout", "3", url + "/health"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "ok" in r.stdout.lower():
                print("  Step-CA ativo (tentativa " + str(i) + ").")
                return True
        except Exception:
            pass
        print("  Tentativa " + str(i) + "/" + str(tentativas))
        time.sleep(intervalo)
    print("  Step-CA NAO respondeu!")
    return False

def desativar_systemd_resolved():
    """Desativa systemd-resolved que ocupa porta 53 e protege /etc/resolv.conf."""
    print("\n--- DESATIVANDO systemd-resolved (libera porta 53) ---")
    run_command(["sudo", "systemctl", "stop", "systemd-resolved"], check=False)
    run_command(["sudo", "systemctl", "disable", "systemd-resolved"], check=False)
    run_command(["sudo", "chattr", "-i", "/etc/resolv.conf"], check=False)
    run_command(["sudo", "rm", "-f", "/etc/resolv.conf"], check=False)
    resolv = "search " + REALM.lower() + "\nnameserver 127.0.0.1\n"
    with open("/tmp/resolv.conf.tmp", "w") as f:
        f.write(resolv)
    run_command(["sudo", "mv", "/tmp/resolv.conf.tmp", "/etc/resolv.conf"])
    run_command(["sudo", "chattr", "+i", "/etc/resolv.conf"])
    print("systemd-resolved desativado, resolv.conf protegido com chattr +i.")

def configuracao_iptables_completa():
    print("\n--- CONFIGURANDO IPTABLES PARA AD DC + PKI ---")
    for port in [53, 88, 135, 139, 389, 445, 464, 636, 8443, 3268, 3269, 5353, 1433, 1521, 8095]:
        run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], check=False)
    for port in [53, 88, 123, 137, 138, 389, 464, 1433, 1521, 5353]:
        run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], check=False)
    run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "49152:65535", "-j", "ACCEPT"], check=False)
    run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "49152:65535", "-j", "ACCEPT"], check=False)
    run_command(["sudo", "iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"], check=False)
    run_command(["sudo", "iptables", "-I", "INPUT", "1", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=False)
    run_command("sudo sh -c 'iptables-save > /etc/sysconfig/iptables 2>/dev/null || true'", shell=True, check=False)
    print("Iptables verificado e atualizado.")

def instalar_e_configurar_step_ca():
    print("\n--- INSTALANDO E CONFIGURANDO STEP-CA ---")
    repo = "[smallstep]\nname=Smallstep\nbaseurl=https://packages.smallstep.com/stable/fedora/\nenabled=1\nrepo_gpgcheck=0\ngpgcheck=1\ngpgkey=https://packages.smallstep.com/keys/smallstep-0x889B19391F774443.gpg\n"
    create_file_with_content("/etc/yum.repos.d/smallstep.repo", repo)
    run_command(["sudo", "dnf", "install", "-y", "step-cli", "step-ca"], check=False)
    run_command(["sudo", "useradd", "--user-group", "--system", "--home-dir", STEP_CA_DIR, "--shell", "/bin/false", "step"], check=False)
    run_command(["sudo", "mkdir", "-p", CERT_DIR], check=False)
    run_command(["sudo", "mkdir", "-p", STEP_CA_DIR], check=False)
    run_command(["sudo", "chmod", "700", CERT_DIR], check=False)
    run_command(["sudo", "chmod", "700", STEP_CA_DIR], check=False)
    run_command(["sudo", "chown", "-R", "step:step", STEP_CA_DIR], check=False)

    with open("/tmp/ca_password.txt", "w") as f:
        f.write(CERT_PWD)
    run_command(["sudo", "mv", "/tmp/ca_password.txt", STEP_CA_PASSWORD_FILE])
    run_command(["sudo", "chmod", "600", STEP_CA_PASSWORD_FILE])
    run_command(["sudo", "chown", "step:step", STEP_CA_PASSWORD_FILE])

    if not os.path.exists(STEP_CA_CONFIG):
        run_command(["sudo", "-u", "step", "STEPPATH=" + STEP_CA_DIR, "step", "ca", "init",
                     "--name", REALM.split('.')[0] + " Root CA",
                     "--dns", HOSTNAME_COMPLETO,
                     "--dns", "ca." + REALM.lower(),
                     "--dns", "pki." + REALM.lower(),
                     "--address", IP_ESTATICO + ":8443",
                     "--provisioner", "admin@" + REALM.lower(),
                     "--password-file", STEP_CA_PASSWORD_FILE,
                     "--deployment-type", "standalone"], check=False)

    if os.path.exists(STEP_CA_CONFIG):
        try:
            with open(STEP_CA_CONFIG, 'r') as f:
                config = json.load(f)
            provs = config.setdefault("authority", {}).setdefault("provisioners", [])
            for p in provs:
                c = p.setdefault("claims", {})
                c["maxTLSCertDuration"] = "8760h"
                c["defaultTLSCertDuration"] = "8760h"
                c["disableRenewal"] = False
            if not any(p.get("type") == "ACME" for p in provs):
                provs.append({"type": "ACME", "name": "dc-auto-enroll", "claims": {"maxTLSCertDuration": "8760h", "defaultTLSCertDuration": "8760h", "disableRenewal": False}})
            ac = config.setdefault("authority", {}).setdefault("claims", {})
            ac.setdefault("maxTLSCertDuration", "8760h")
            ac.setdefault("defaultTLSCertDuration", "8760h")
            with open("/tmp/ca_config_fixed.json", "w") as f:
                json.dump(config, f, indent=2)
            run_command(["sudo", "mv", "/tmp/ca_config_fixed.json", STEP_CA_CONFIG])
            run_command(["sudo", "chown", "step:step", STEP_CA_CONFIG])
        except Exception as e:
            print("Aviso ao ajustar json do step-ca: " + str(e))

    svc = "[Unit]\nDescription=Step Certificate Authority\nAfter=network-online.target\nWants=network-online.target\nConditionFileNotEmpty=" + STEP_CA_CONFIG + "\nConditionFileNotEmpty=" + STEP_CA_PASSWORD_FILE + "\n\n[Service]\nType=simple\nUser=step\nGroup=step\nEnvironment=STEPPATH=" + STEP_CA_DIR + "\nWorkingDirectory=" + STEP_CA_DIR + "\nExecStart=/usr/bin/step-ca config/ca.json --password-file password.txt\nRestart=on-failure\nRestartSec=5\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=yes\nProtectSystem=full\nProtectHome=true\nPrivateTmp=true\nPrivateDevices=true\nReadWritePaths=" + STEP_CA_DIR + "/db\n\n[Install]\nWantedBy=multi-user.target\n"
    create_file_with_content("/etc/systemd/system/step-ca.service", svc)
    run_command(["sudo", "systemctl", "daemon-reload"])
    run_command(["sudo", "systemctl", "enable", "step-ca"], check=False)
    run_command(["sudo", "systemctl", "start", "step-ca"], check=False)

    san_args = []
    for s in CERT_SANS:
        if s.startswith("DNS:"):
            san_args += ["--san", s[4:]]
        elif s.startswith("IP:"):
            san_args += ["--san", s[3:]]

    run_command(["sudo", "-u", "step", "STEPPATH=" + STEP_CA_DIR, "step", "ca", "certificate",
                 HOSTNAME_COMPLETO, "/tmp/dc.crt", "/tmp/dc.key",
                 "--provisioner", "admin@" + REALM.lower(),
                 "--password-file", STEP_CA_PASSWORD_FILE,
                 "--kty", "RSA", "--size", "2048", "--not-after", "8760h"] + san_args, check=False)

    if os.path.exists("/tmp/dc.crt") and os.path.exists("/tmp/dc.key"):
        run_command(["sudo", "mv", "/tmp/dc.crt", CERT_PATH])
        run_command(["sudo", "mv", "/tmp/dc.key", KEY_PATH])
        run_command(["sudo", "chmod", "600", KEY_PATH])
        run_command(["sudo", "chmod", "644", CERT_PATH])
        run_command(["sudo", "chown", "root:root", KEY_PATH, CERT_PATH])

    if os.path.exists(STEP_CA_ROOT_CERT):
        run_command(["sudo", "cp", STEP_CA_ROOT_CERT, "/etc/pki/ca-trust/source/anchors/step-ca-root.crt"], check=False)
        run_command(["sudo", "update-ca-trust"], check=False)
        run_command(["sudo", "cp", STEP_CA_ROOT_CERT, CERT_DIR + "/step-ca-root.crt"], check=False)

    renew_sh = "#!/bin/bash\nset -euo pipefail\nexport STEPPATH=\"" + STEP_CA_DIR + "\"\nCERT=\"" + CERT_PATH + "\"\nKEY=\"" + KEY_PATH + "\"\nLOG=\"" + RENEW_LOG + "\"\nif [ ! -f \"$CERT\" ]; then exit 1; fi\nif ! openssl x509 -in \"$CERT\" -checkend 604800 2>/dev/null | grep -q \"Certificate will expire\"; then exit 0; fi\nCA_URL=\"https://" + IP_ESTATICO + ":8443\"\nif ! curl -sk --connect-timeout 10 \"$CA_URL/health\" >/dev/null 2>&1; then\n  systemctl start step-ca 2>>\"$LOG\" || true\n  sleep 5\nfi\nfor i in 1 2 3; do\n  if step ca renew \"$CERT\" \"$KEY\" --force --mtls=false >>\"$LOG\" 2>&1; then\n    systemctl reload samba >>\"$LOG\" 2>&1 || systemctl restart samba >>\"$LOG\" 2>&1 || true\n    exit 0\n  fi\n  sleep $((30 * i))\ndone\nexit 1\n"
    create_file_with_content("/usr/local/bin/step-ca-renew.sh", renew_sh)
    run_command(["sudo", "chmod", "+x", "/usr/local/bin/step-ca-renew.sh"])

    renew_svc = "[Unit]\nDescription=Renovacao Step-CA\nAfter=network-online.target step-ca.service samba.service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/step-ca-renew.sh\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n"
    create_file_with_content("/etc/systemd/system/step-ca-renew.service", renew_svc)
    renew_tmr = "[Unit]\nDescription=Timer renovacao Step-CA\nRequires=step-ca-renew.service\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nRandomizedDelaySec=900\nAccuracySec=1m\n\n[Install]\nWantedBy=timers.target\n"
    create_file_with_content("/etc/systemd/system/step-ca-renew.timer", renew_tmr)
    run_command(["sudo", "systemctl", "daemon-reload"])
    run_command(["sudo", "systemctl", "enable", "--now", "step-ca-renew.timer"], check=False)
    print("Step-CA configurado com renovação automática e TLS para LDAPS.")

def configurar_chrony_ntp():
    print("\n--- CONFIGURANDO CHRONY NTP ---")
    conf = "pool 2.br.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\nlocal stratum 10\nntpsigndsocket /var/lib/samba/ntp_signd\n"
    create_file_with_content("/etc/chrony.conf", conf)
    run_command(["sudo", "install", "-d", "-o", "root", "-g", "chrony", "-m", "750", "/var/lib/samba/ntp_signd"], check=False)
    run_command(["sudo", "systemctl", "enable", "--now", "chronyd"], check=False)
    print("NTP Chrony configurado com signed socket do Samba.")

def atualizar_schema_e_niveis():
    print("\n--- ELEVANDO SCHEMA 2019 E FUNCIONAL LEVEL 2016 ---")
    update_smb_conf(["ad dc functional level = 2016"])
    run_command(["sudo", "systemctl", "restart", "samba"], check=False)
    run_command(["sudo", "systemctl", "stop", "samba"], check=False)
    run_command(["sudo", "samba-tool", "domain", "schemaupgrade", "--schema=2019"], check=False)
    run_command(["sudo", "samba-tool", "domain", "functionalprep", "--function-level=2016"], check=False)
    run_command(["sudo", "samba-tool", "domain", "level", "raise", "--domain-level=2016", "--forest-level=2016"], check=False)
    run_command(["sudo", "systemctl", "start", "samba"], check=False)
    run_command(["sudo", "samba-tool", "dbcheck", "--cross-ncs", "--fix", "--yes"], check=False)
    esperar_samba_ldap(tentativas=10, intervalo=3)
    print("Schema 2019 e Níveis 2016 aplicados.")

def corrigir_particoes_dns():
    print("\n--- CORRIGINDO PARTIÇÕES DNS (msDS-SDReferenceDomain) ---")
    fix_py = (
        "#!/usr/bin/python3\n"
        "import sys, optparse\n"
        "from samba.auth import system_session\n"
        "from samba.credentials import Credentials\n"
        "from samba.samdb import SamDB\n"
        "import samba.getopt as options\n"
        "try:\n"
        "    parser = optparse.OptionParser()\n"
        "    sambaopts = options.SambaOptions(parser)\n"
        "    lp = sambaopts.get_loadparm()\n"
        "    creds = Credentials()\n"
        "    creds.guess(lp)\n"
        "    samdb = SamDB(session_info=system_session(), credentials=creds, lp=lp)\n"
        "    domain_dn = samdb.get_default_basedn()\n"
        "    domain_name = lp.get('realm').lower()\n"
        "    partitions_dn = 'CN=Partitions,' + str(samdb.get_config_basedn())\n"
        "    flt = '(|(dnsRoot=DomainDnsZones.' + domain_name + ')(dnsRoot=ForestDnsZones.' + domain_name + '))'\n"
        "    for p in samdb.search(base=partitions_dn, expression=flt, scope=1):\n"
        "        if 'msDS-SDReferenceDomain' not in p:\n"
        "            ldif = 'dn: ' + str(p['dn']) + '\\nchangetype: modify\\nreplace: msDS-SDReferenceDomain\\nmsDS-SDReferenceDomain: ' + str(domain_dn) + '\\n'\n"
        "            samdb.modify_ldif(ldif)\n"
        "            print('  Corrigido: ' + str(p['dn']))\n"
        "        else:\n"
        "            print('  OK: ' + str(p['dn']))\n"
        "    print('Concluido com sucesso.')\n"
        "except Exception as e:\n"
        "    print('Aviso: ' + str(e))\n"
    )
    create_file_with_content("/tmp/fix_dns_partitions.py", fix_py)
    run_command(["sudo", "python3", "/tmp/fix_dns_partitions.py"], check=False)
    run_command(["sudo", "rm", "-f", "/tmp/fix_dns_partitions.py"], check=False)
    print("Partições DNS corrigidas.")

def configurar_zonas_reversas_e_ca():
    print("\n--- CONFIGURANDO ZONAS REVERSAS E REGISTROS CA ---")
    if not esperar_samba_ldap(tentativas=10, intervalo=3):
        print("Samba não disponível. Pulando configuração de registros DNS.")
        return

    octetos = IP_ESTATICO.split('.')
    zona_reversa = '.'.join(reversed(octetos[:3])) + '.in-addr.arpa'
    ultimo_octeto = octetos[-1]

    cred = ADMIN_USER + "%" + SENHA_ADMIN
    base_cmd = ["sudo", "samba-tool", "dns"]

    def run_dns(args, desc):
        cmd = base_cmd + args + ["-U", cred]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0 or "already exists" in (r.stdout + r.stderr).lower():
                print("  OK: " + desc)
                return True
            else:
                print("  Aviso (" + desc + "): " + r.stderr.strip()[:100])
                return False
        except Exception as e:
            print("  Erro (" + desc + "): " + str(e))
            return False

    run_dns(["zonecreate", HOSTNAME_COMPLETO, zona_reversa], "Zona Reversa " + zona_reversa)
    run_dns(["add", HOSTNAME_COMPLETO, zona_reversa, ultimo_octeto, "PTR", HOSTNAME_COMPLETO], "PTR " + ultimo_octeto)
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(), "ca", "A", IP_ESTATICO], "A ca." + REALM.lower())
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(), "pki", "CNAME", "ca." + REALM.lower()], "CNAME pki." + REALM.lower())
    print("Zonas reversas e registros CA configurados com sucesso.")

def main():
    parser = argparse.ArgumentParser(description="Automação Samba AD DC + Step-CA PKI + DNS")
    parser.add_argument("--non-interactive", action="store_true", help="Executar sem pausar para confirmação")
    parser.add_argument("--step-ca-only", action="store_true", help="Configurar apenas Step-CA e certificados TLS")
    parser.add_argument("--schema-only", action="store_true", help="Executar apenas elevação de schema e níveis")
    parser.add_argument("--dns-fix-only", action="store_true", help="Corrigir apenas partições DNS e zonas reversas")
    args = parser.parse_args()

    global NON_INTERACTIVE
    if args.non_interactive:
        NON_INTERACTIVE = True

    if args.step_ca_only:
        instalar_e_configurar_step_ca()
        return

    if args.schema_only:
        atualizar_schema_e_niveis()
        return

    if args.dns_fix_only:
        corrigir_particoes_dns()
        configurar_zonas_reversas_e_ca()
        return

    print("=" * 70)
    print(" Astral AD & Hybrid DNS - Provisionador Avançado Samba AD + Step-CA")
    print(" Realm: " + REALM + " | Host: " + HOSTNAME_COMPLETO)
    print("=" * 70)
    wait_for_enter("Pressione Enter para iniciar...")

    desativar_systemd_resolved()
    configuracao_iptables_completa()
    configurar_chrony_ntp()
    instalar_e_configurar_step_ca()
    atualizar_schema_e_niveis()
    corrigir_particoes_dns()
    configurar_zonas_reversas_e_ca()

    print("\n" + "=" * 70)
    print("Provisionamento e melhorias concluídas com sucesso!")
    print("=" * 70)

if __name__ == "__main__":
    main()
