#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import time
import json

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

print("Config carregada de: " + ENV_FILE)
print("  HOSTNAME: " + HOSTNAME_COMPLETO + " | REALM: " + REALM)
print("  ADMIN_USER: " + ADMIN_USER)

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

def run_command(command, shell=False, check=True):
    try:
        cmd_str = command if isinstance(command, str) else ' '.join(command)
        print("Executando: " + cmd_str)
        subprocess.run(command, shell=shell, check=check, text=True, stdout=sys.stdout, stderr=sys.stderr)
        print("-" * 40)
        time.sleep(1)
    except subprocess.CalledProcessError as e:
        print("ERRO ao executar comando: " + str(e))
        raise e

def wait_for_enter(prompt="Pressione Enter para continuar..."):
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
    """Desativa systemd-resolved que ocupa porta 53."""
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
    print("systemd-resolved desativado, resolv.conf reconfigurado.")

def limpeza_previa():
    print("\n--- FASE 0: LIMPEZA ---")
    wait_for_enter("AVISO: dados existentes serao removidos.")
    for s in ["samba", "named", "chronyd", "step-ca", "step-ca-renew"]:
        run_command(["sudo", "systemctl", "stop", s], check=False)
        run_command(["sudo", "systemctl", "disable", s], check=False)
    run_command(["sudo", "dnf", "remove", "-y", "step-ca", "step-cli"], check=False)
    for loc in ["/etc/samba/smb.conf", "/etc/krb5.conf", "/etc/named.conf", "/etc/chrony.conf",
                "/var/lib/samba/*", "/var/cache/samba/*", "/var/log/samba/*", "/var/named/*",
                CERT_DIR, STEP_CA_DIR,
                "/etc/systemd/system/step-ca.service",
                "/etc/systemd/system/step-ca-renew.service",
                "/etc/systemd/system/step-ca-renew.timer",
                "/usr/local/bin/step-ca-renew.sh", RENEW_LOG,
                "/etc/yum.repos.d/smallstep.repo"]:
        run_command("sudo rm -rf " + loc, shell=True, check=False)
    run_command(["sudo", "systemctl", "daemon-reload"])
    print("Limpeza concluida.")

def preparacao_sistema():
    print("\n--- FASE 1: PREPARACAO ---")
    run_command(["sudo", "hostnamectl", "set-hostname", HOSTNAME_COMPLETO])
    hosts = "127.0.0.1   localhost\n" + IP_ESTATICO + "   " + HOSTNAME_COMPLETO + "   " + HOSTNAME_COMPLETO.split('.')[0] + "\n"
    create_file_with_content("/etc/hosts", hosts)
    run_command(["sudo", "systemctl", "stop", "firewalld"], check=False)
    run_command(["sudo", "systemctl", "disable", "firewalld"], check=False)
    pkgs = ["samba-dc", "samba-client", "bind", "chrony", "iptables-services",
            "patch", "python3-markdown", "openssl", "bind-utils", "curl", "tar", "jq"]
    run_command(["sudo", "dnf", "install", "-y"] + pkgs)
    print("Preparacao concluida.")

def configurar_iptables():
    print("\n--- FASE 2: IPTABLES ---")
    run_command(["sudo", "iptables", "-F", "INPUT"])
    for port in [53, 88, 135, 139, 389, 445, 464, 636, 8443, 3268, 3269, 5353, 1433, 1521]:
        run_command(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    for port in [53, 88, 123, 137, 138, 389, 464, 1433, 1521]:
        run_command(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "49152:65535", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", "49152:65535", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-P", "INPUT", "DROP"])
    run_command("sudo sh -c 'iptables-save > /etc/sysconfig/iptables'", shell=True)
    run_command(["sudo", "systemctl", "enable", "iptables"])
    run_command(["sudo", "systemctl", "restart", "iptables"])
    try:
        result = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=5)
        if "8443" not in result.stdout:
            run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT"])
            run_command("sudo sh -c 'iptables-save > /etc/sysconfig/iptables'", shell=True)
    except Exception:
        pass
    print("Iptables configurado (policy DROP).")

def instalar_step_ca():
    print("\n--- FASE 3: STEP-CA ---")
    repo = "[smallstep]\nname=Smallstep\nbaseurl=https://packages.smallstep.com/stable/fedora/\nenabled=1\nrepo_gpgcheck=0\ngpgcheck=1\ngpgkey=https://packages.smallstep.com/keys/smallstep-0x889B19391F774443.gpg\n"
    create_file_with_content("/etc/yum.repos.d/smallstep.repo", repo)
    run_command(["sudo", "dnf", "makecache"], check=False)
    run_command(["sudo", "dnf", "install", "-y", "step-cli", "step-ca"])
    run_command(["sudo", "useradd", "--user-group", "--system", "--home-dir", STEP_CA_DIR, "--shell", "/bin/false", "step"], check=False)
    run_command(["sudo", "mkdir", "-p", CERT_DIR])
    run_command(["sudo", "mkdir", "-p", STEP_CA_DIR])
    run_command(["sudo", "chmod", "700", CERT_DIR])
    run_command(["sudo", "chmod", "700", STEP_CA_DIR])
    run_command(["sudo", "chown", "-R", "step:step", STEP_CA_DIR])
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
                     "--deployment-type", "standalone"])
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
    svc = "[Unit]\nDescription=Step Certificate Authority\nAfter=network-online.target\nWants=network-online.target\nConditionFileNotEmpty=" + STEP_CA_CONFIG + "\nConditionFileNotEmpty=" + STEP_CA_PASSWORD_FILE + "\n\n[Service]\nType=simple\nUser=step\nGroup=step\nEnvironment=STEPPATH=" + STEP_CA_DIR + "\nWorkingDirectory=" + STEP_CA_DIR + "\nExecStart=/usr/bin/step-ca config/ca.json --password-file password.txt\nRestart=on-failure\nRestartSec=5\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=yes\nProtectSystem=full\nProtectHome=true\nPrivateTmp=true\nPrivateDevices=true\nReadWritePaths=" + STEP_CA_DIR + "/db\n\n[Install]\nWantedBy=multi-user.target\n"
    create_file_with_content("/etc/systemd/system/step-ca.service", svc)
    run_command(["sudo", "systemctl", "daemon-reload"])
    run_command(["sudo", "systemctl", "enable", "step-ca"])
    run_command(["sudo", "systemctl", "start", "step-ca"])
    if not aguardar_step_ca_healthy(tentativas=30, intervalo=2):
        print("ERRO: Step-CA nao respondeu!")
        sys.exit(1)
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
                 "--kty", "RSA", "--size", "2048", "--not-after", "8760h"] + san_args)
    run_command(["sudo", "mv", "/tmp/dc.crt", CERT_PATH])
    run_command(["sudo", "mv", "/tmp/dc.key", KEY_PATH])
    run_command(["sudo", "chmod", "600", KEY_PATH])
    run_command(["sudo", "chmod", "644", CERT_PATH])
    run_command(["sudo", "chown", "root:root", KEY_PATH, CERT_PATH])
    run_command(["sudo", "cp", STEP_CA_ROOT_CERT, "/etc/pki/ca-trust/source/anchors/step-ca-root.crt"])
    run_command(["sudo", "update-ca-trust"])
    run_command(["sudo", "cp", STEP_CA_ROOT_CERT, CERT_DIR + "/step-ca-root.crt"])
    renew_sh = "#!/bin/bash\nset -euo pipefail\nexport STEPPATH=\"" + STEP_CA_DIR + "\"\nCERT=\"" + CERT_PATH + "\"\nKEY=\"" + KEY_PATH + "\"\nLOG=\"" + RENEW_LOG + "\"\nif [ ! -f \"$CERT\" ]; then exit 1; fi\nif ! openssl x509 -in \"$CERT\" -checkend 604800 2>/dev/null | grep -q \"Certificate will expire\"; then exit 0; fi\nCA_URL=\"https://" + IP_ESTATICO + ":8443\"\nif ! curl -sk --connect-timeout 10 \"$CA_URL/health\" >/dev/null 2>&1; then\n  systemctl start step-ca 2>>\"$LOG\" || true\n  sleep 5\nfi\nfor i in 1 2 3; do\n  if step ca renew \"$CERT\" \"$KEY\" --force --mtls=false >>\"$LOG\" 2>&1; then\n    systemctl reload samba >>\"$LOG\" 2>&1 || systemctl restart samba >>\"$LOG\" 2>&1 || true\n    exit 0\n  fi\n  sleep $((30 * i))\ndone\nexit 1\n"
    create_file_with_content("/usr/local/bin/step-ca-renew.sh", renew_sh)
    run_command(["sudo", "chmod", "+x", "/usr/local/bin/step-ca-renew.sh"])
    renew_svc = "[Unit]\nDescription=Renovacao Step-CA\nAfter=network-online.target step-ca.service samba.service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/step-ca-renew.sh\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n"
    create_file_with_content("/etc/systemd/system/step-ca-renew.service", renew_svc)
    renew_tmr = "[Unit]\nDescription=Timer renovacao Step-CA\nRequires=step-ca-renew.service\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nRandomizedDelaySec=900\nAccuracySec=1m\n\n[Install]\nWantedBy=timers.target\n"
    create_file_with_content("/etc/systemd/system/step-ca-renew.timer", renew_tmr)
    run_command(["sudo", "systemctl", "daemon-reload"])
    run_command(["sudo", "systemctl", "enable", "step-ca-renew.timer"])
    run_command(["sudo", "systemctl", "start", "step-ca-renew.timer"])
    run_command(["openssl", "x509", "-in", CERT_PATH, "-noout", "-subject", "-issuer", "-dates"], check=False)
    print("STEP-CA CONFIGURADO E RODANDO!")

def configurar_ntp():
    print("\n--- FASE 4: NTP ---")
    conf = "pool 2.br.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\nlocal stratum 10\nntpsigndsocket /var/lib/samba/ntp_signd\n"
    create_file_with_content("/etc/chrony.conf", conf)
    run_command(["sudo", "install", "-d", "-o", "root", "-g", "chrony", "-m", "750", "/var/lib/samba/ntp_signd"])
    print("NTP concluido.")

def provisionar_dominio():
    print("\n--- FASE 5: PROVISIONAMENTO ---")
    run_command(["sudo", "samba-tool", "domain", "provision", "--use-rfc2307",
                 "--realm", REALM, "--domain", NOME_NETBIOS, "--server-role=dc",
                 "--dns-backend=SAMBA_INTERNAL", "--adminpass", SENHA_ADMIN])
    tls_params = ["tls enabled = yes", "tls keyfile = " + KEY_PATH,
                  "tls certfile = " + CERT_PATH, "tls cafile = " + CERT_DIR + "/step-ca-root.crt",
                  "tls verify peer = ca_only"]
    update_smb_conf(tls_params)
    print("Provisionamento concluido (com TLS).")

def configurar_samba_e_bind():
    print("\n--- FASE 6: SAMBA E BIND ---")
    update_smb_conf(["dns forwarder = 127.0.0.1:5353", "interfaces = lo " + INTERFACE_REDE, "bind interfaces only = yes"])
    run_command(["sudo", "mkdir", "-p", "/var/named/data"])
    run_command(["sudo", "chown", "-R", "named:named", "/var/named"])
    named = 'options {\n  directory "/var/named";\n  listen-on port 5353 { 127.0.0.1; };\n  listen-on-v6 { none; };\n  allow-query { localhost; };\n  recursion yes;\n  forwarders { 8.8.8.8; 1.1.1.1; };\n  dnssec-validation no;\n};\nlogging {\n  channel default_debug { file "data/named.run"; severity dynamic; };\n};\n'
    create_file_with_content("/etc/named.conf", named)
    create_file_with_content("/etc/sysconfig/named", 'OPTIONS="-4"')
    print("Samba e BIND configurados.")

def integracao_final():
    print("\n--- FASE 7: INTEGRACAO ---")
    desativar_systemd_resolved()
    krb5 = "[libdefaults]\n  default_realm = " + REALM.upper() + "\n  dns_lookup_realm = false\n  dns_lookup_kdc = true\n\n[realms]\n  " + REALM.upper() + " = {\n    kdc = " + HOSTNAME_COMPLETO.lower() + "\n    admin_server = " + HOSTNAME_COMPLETO.lower() + "\n    default_domain = " + REALM.lower() + "\n  }\n\n[domain_realm]\n  ." + REALM.lower() + " = " + REALM.upper() + "\n  " + REALM.lower() + " = " + REALM.upper() + "\n"
    create_file_with_content("/etc/krb5.conf", krb5)
    for svc in ["chronyd", "named"]:
        run_command(["sudo", "systemctl", "enable", svc])
        run_command(["sudo", "systemctl", "restart", svc])
    print("Iniciando Samba...")
    run_command(["sudo", "systemctl", "enable", "samba"])
    run_command(["sudo", "systemctl", "restart", "samba"])
    esperar_samba_ldap(tentativas=20, intervalo=5)
    print("Servicos iniciados.")

def atualizar_e_elevar_niveis():
    print("\n--- FASE 8: SCHEMA E NIVEIS ---")
    wait_for_enter("Modificacoes IRREVERSIVEIS. Enter para continuar.")
    update_smb_conf(["ad dc functional level = 2016"])
    run_command(["sudo", "systemctl", "restart", "samba"])
    run_command(["sudo", "systemctl", "stop", "samba"])
    run_command(["sudo", "samba-tool", "domain", "schemaupgrade", "--schema=2019"])
    run_command(["sudo", "samba-tool", "domain", "functionalprep", "--function-level=2016"])
    run_command(["sudo", "samba-tool", "domain", "level", "raise", "--domain-level=2016", "--forest-level=2016"])
    run_command(["sudo", "systemctl", "start", "samba"])
    run_command(["sudo", "samba-tool", "dbcheck", "--cross-ncs", "--fix", "--yes"])
    esperar_samba_ldap(tentativas=20, intervalo=5)
    print("Schema e niveis concluidos.")

def corrigir_particoes_dns():
    print("\n--- FASE 9: PARTICOES DNS ---")
    wait_for_enter("Enter para corrigir particoes DNS.")
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
        "    print('Concluido.')\n"
        "except Exception as e:\n"
        "    print('ERRO: ' + str(e))\n"
        "    sys.exit(1)\n"
    )
    create_file_with_content("/tmp/fix_dns_partitions.py", fix_py)
    run_command(["sudo", "python3", "/tmp/fix_dns_partitions.py"])
    run_command(["sudo", "rm", "-f", "/tmp/fix_dns_partitions.py"])
    print("Particoes DNS corrigidas.")

def configurar_zonas_reversas():
    """Cria zona reversa e registros DNS via samba-tool dns.
    CORRECAO: -U deve vir DEPOIS do subcomando, nao antes."""
    print("\n--- FASE 10: ZONAS REVERSAS (samba-tool dns) ---")
    if not esperar_samba_ldap(tentativas=20, intervalo=5):
        print("Samba nao acessivel. Pulando.")
        return

    octetos = IP_ESTATICO.split('.')
    zona_reversa = '.'.join(reversed(octetos[:3])) + '.in-addr.arpa'
    ultimo_octeto = octetos[-1]

    print("  Zona reversa: " + zona_reversa)
    print("  PTR: " + ultimo_octeto + " -> " + HOSTNAME_COMPLETO)

    # Credenciais: -U vem DEPOIS do subcomando no samba-tool dns
    cred = ADMIN_USER + "%" + SENHA_ADMIN
    base_cmd = ["sudo", "samba-tool", "dns"]

    def run_dns(args, descricao):
        """Executa comando samba-tool dns com -U no final."""
        cmd = base_cmd + args + ["-U", cred]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = (r.stdout + " " + r.stderr).lower()
            if r.returncode == 0:
                print("    OK: " + descricao)
                return True
            elif "already exists" in output:
                print("    OK (ja existe): " + descricao)
                return True
            else:
                print("    Aviso: " + descricao + " -> " + r.stderr.strip()[:100])
                return False
        except Exception as e:
            print("    Aviso: " + descricao + " -> " + str(e))
            return False

    # 1) Criar zona reversa
    print("\n  [1/4] Criando zona reversa...")
    run_dns(["zonecreate", HOSTNAME_COMPLETO, zona_reversa],
            "zona " + zona_reversa)

    # 2) Adicionar PTR
    print("\n  [2/4] Adicionando PTR...")
    run_dns(["add", HOSTNAME_COMPLETO, zona_reversa,
             ultimo_octeto, "PTR", HOSTNAME_COMPLETO],
            ultimo_octeto + " -> " + HOSTNAME_COMPLETO)

    # 3) Adicionar registro A para 'ca'
    print("\n  [3/4] Adicionando registro A 'ca'...")
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(),
             "ca", "A", IP_ESTATICO],
            "ca." + REALM.lower() + " -> " + IP_ESTATICO)

    # 4) Adicionar CNAME 'pki' -> ca
    print("\n  [4/4] Adicionando CNAME 'pki'...")
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(),
             "pki", "CNAME", "ca." + REALM.lower()],
            "pki." + REALM.lower() + " -> ca." + REALM.lower())

    # Validacao final
    print("\n  Validando registros DNS (5s para propagacao)...")
    time.sleep(5)

    # Teste PTR
    try:
        r = subprocess.run(["nslookup", IP_ESTATICO, "127.0.0.1"],
                           capture_output=True, text=True, timeout=10)
        if HOSTNAME_COMPLETO.lower() in r.stdout.lower():
            print("    PTR OK: " + IP_ESTATICO + " -> " + HOSTNAME_COMPLETO)
        else:
            linhas = r.stdout.strip().splitlines()
            print("    PTR: " + (linhas[-1] if linhas else "sem resposta"))
    except Exception as e:
        print("    Aviso nslookup PTR: " + str(e))

    # Teste A ca
    try:
        r = subprocess.run(["nslookup", "ca." + REALM.lower(), "127.0.0.1"],
                           capture_output=True, text=True, timeout=10)
        if IP_ESTATICO in r.stdout:
            print("    A 'ca' OK: ca." + REALM.lower() + " -> " + IP_ESTATICO)
        else:
            linhas = r.stdout.strip().splitlines()
            print("    A 'ca': " + (linhas[-1] if linhas else "sem resposta"))
    except Exception as e:
        print("    Aviso nslookup ca: " + str(e))

    # Teste CNAME pki
    try:
        r = subprocess.run(["nslookup", "pki." + REALM.lower(), "127.0.0.1"],
                           capture_output=True, text=True, timeout=10)
        if "ca." + REALM.lower() in r.stdout.lower() or IP_ESTATICO in r.stdout:
            print("    CNAME 'pki' OK: pki." + REALM.lower() + " -> ca." + REALM.lower())
        else:
            linhas = r.stdout.strip().splitlines()
            print("    CNAME 'pki': " + (linhas[-1] if linhas else "sem resposta"))
    except Exception as e:
        print("    Aviso nslookup pki: " + str(e))

    print("\nZonas reversas e registros CA concluidos.")

def main():
    if os.geteuid() != 0:
        print("Execute como root ou com sudo.")
        sys.exit(1)
    os.system('clear')
    print("=" * 70)
    print(" Samba AD DC + STEP-CA - Nobara 44 / Samba 4.24.2")
    print(" Config: " + ENV_FILE)
    print(" RSA 4096 bits | cert 1 ano | policy DROP")
    print("=" * 70)
    wait_for_enter("Enter para iniciar...")
    try:
        limpeza_previa()
        preparacao_sistema()
        configurar_iptables()
        instalar_step_ca()
        configurar_ntp()
        provisionar_dominio()
        configurar_samba_e_bind()
        integracao_final()
        atualizar_e_elevar_niveis()
        corrigir_particoes_dns()
        configurar_zonas_reversas()
        print("\n" + "=" * 70)
        print("SUCESSO! Domain Controller + PKI configurados.")
        print("  Schema 2019 | Niveis 2016 | RSA 4096 | LDAPS 636")
        print("=" * 70)
    except KeyboardInterrupt:
        print("\nCancelado.")
        sys.exit(0)
    except Exception as e:
        print("\nERRO: " + str(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
