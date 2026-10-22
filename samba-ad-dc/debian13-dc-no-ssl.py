#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Debian 13 Samba AD DC - Sem SSL/TLS
Baseado na documentação da Tranquilit
Usa auth.env para configurações
"""
import os
import subprocess
import sys
import time

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
    obrig = ["HOSTNAME_COMPLETO", "NOME_NETBIOS", "REALM", "IP_ESTATICO", "INTERFACE_REDE", "SENHA_ADMIN"]
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

print("Config carregada de: " + ENV_FILE)
print("  HOSTNAME: " + HOSTNAME_COMPLETO + " | REALM: " + REALM)
print("  ADMIN_USER: " + ADMIN_USER)

CERT_DIR = "/etc/samba/tls"

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

def configurar_apparmor():
    """Configura perfis do AppArmor para Samba e BIND no Debian."""
    print("\n--- CONFIGURANDO APPARMOR ---")

    # Perfil para Samba AD DC
    samba_profile = """# Profile for Samba AD DC
#include <tunables/global>

/usr/sbin/samba flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/authentication>
  #include <abstractions/certs>
  #include <abstractions/openssl>
  #include <abstractions/pam>
  #include <abstractions/dbus-strict>
  #include <abstractions/nss>

  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability fsetid,
  capability kill,
  capability setgid,
  capability setuid,
  capability net_bind_service,
  capability sys_admin,
  capability sys_resource,

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network netlink raw,

  /etc/samba/** rw,
  /var/lib/samba/** rw,
  /var/cache/samba/** rw,
  /var/log/samba/** rw,
  /run/samba/** rw,
  /etc/krb5.conf r,
  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/passwd r,
  /etc/group r,
  /etc/shadow r,
  /etc/gshadow r,
  /var/lib/samba/ntp_signd/** rw,
  /run/** mrwk,
  /tmp/** mrwk,
  /dev/urandom r,
  /dev/random r,
  /proc/** r,
  /sys/** r,
}
"""
    create_file_with_content("/etc/apparmor.d/usr.sbin.samba", samba_profile)

    # Perfil para BIND9
    bind_profile = """# Profile for BIND9
#include <tunables/global>

/usr/sbin/named flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/bind>

  capability chown,
  capability setgid,
  capability setuid,
  capability net_bind_service,
  capability dac_override,

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  /etc/bind/** r,
  /var/cache/bind/** rw,
  /var/lib/bind/** rw,
  /var/log/bind9/** rw,
  /run/named/** rw,
  /dev/null rw,
  /dev/zero rw,
  /dev/random r,
  /dev/urandom r,
  /proc/** r,
  /sys/** r,
}
"""
    create_file_with_content("/etc/apparmor.d/usr.sbin.named", bind_profile)

    # Recarregar perfis do AppArmor
    run_command(["sudo", "apparmor_parser", "-r", "/etc/apparmor.d/usr.sbin.samba"], check=False)
    run_command(["sudo", "apparmor_parser", "-r", "/etc/apparmor.d/usr.sbin.named"], check=False)
    run_command(["sudo", "systemctl", "reload", "apparmor"], check=False)

    print("AppArmor configurado em modo complain para Samba e BIND.")

def limpeza_previa():
    print("\n--- FASE 0: LIMPEZA ---")
    wait_for_enter("AVISO: dados existentes serao removidos.")
    for s in ["samba-ad-dc", "bind9", "chrony", "nftables"]:
        run_command(["sudo", "systemctl", "stop", s], check=False)
        run_command(["sudo", "systemctl", "disable", s], check=False)
    for loc in ["/etc/samba/smb.conf", "/etc/krb5.conf", "/etc/bind/named.conf",
                "/etc/bind/named.conf.options", "/etc/bind/named.conf.local",
                "/etc/bind/named.conf.default-zones", "/etc/default/bind9",
                "/var/lib/samba/*", "/var/cache/samba/*", "/var/log/samba/*",
                "/var/cache/bind/*", "/var/lib/bind/*", "/var/log/bind9/*",
                CERT_DIR]:
        run_command("sudo rm -rf " + loc, shell=True, check=False)
    run_command(["sudo", "systemctl", "daemon-reload"])
    print("Limpeza concluida.")

def preparacao_sistema():
    print("\n--- FASE 1: PREPARACAO ---")
    run_command(["sudo", "hostnamectl", "set-hostname", HOSTNAME_COMPLETO])
    hosts = "127.0.0.1   localhost\n" + IP_ESTATICO + "   " + HOSTNAME_COMPLETO + "   " + HOSTNAME_COMPLETO.split('.')[0] + "\n"
    create_file_with_content("/etc/hosts", hosts)
    
    # Desativar nftables e usar iptables
    run_command(["sudo", "systemctl", "stop", "nftables"], check=False)
    run_command(["sudo", "systemctl", "disable", "nftables"], check=False)
    run_command(["sudo", "systemctl", "enable", "iptables-netfilter-persistent"], check=False)
    
    # Atualizar e instalar pacotes
    run_command(["sudo", "apt-get", "update"])
    pkgs = ["samba", "samba-vfs-modules", "bind9", "bind9utils", "bind9-doc",
            "chrony", "iptables", "iptables-persistent", "netfilter-persistent",
            "patch", "python3-markdown", "openssl", "dnsutils", "curl", "jq",
            "apparmor", "apparmor-utils", "libpam-apparmor"]
    run_command(["sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y"] + pkgs)
    print("Preparacao concluida.")

def configurar_iptables():
    print("\n--- FASE 2: IPTABLES ---")
    run_command(["sudo", "iptables", "-F", "INPUT"])
    for port in [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5353, 1433, 1521]:
        run_command(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    for port in [53, 88, 123, 137, 138, 389, 464, 1433, 1521]:
        run_command(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "49152:65535", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", "49152:65535", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-P", "INPUT", "DROP"])
    run_command("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'", shell=True)
    run_command(["sudo", "systemctl", "restart", "netfilter-persistent"])
    try:
        result = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=5)
        if "389" not in result.stdout:
            run_command(["sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "389", "-j", "ACCEPT"])
            run_command("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'", shell=True)
    except Exception:
        pass
    print("Iptables configurado (policy DROP).")

def configurar_ntp():
    print("\n--- FASE 3: NTP ---")
    conf = "pool 2.br.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\nlocal stratum 10\nntpsigndsocket /var/lib/samba/ntp_signd\n"
    create_file_with_content("/etc/chrony/chrony.conf", conf)
    run_command(["sudo", "install", "-d", "-o", "root", "-g", "chrony", "-m", "750", "/var/lib/samba/ntp_signd"])
    run_command(["sudo", "systemctl", "enable", "chrony"])
    run_command(["sudo", "systemctl", "restart", "chrony"])
    print("NTP concluido.")

def provisionar_dominio():
    print("\n--- FASE 4: PROVISIONAMENTO ---")
    run_command(["sudo", "samba-tool", "domain", "provision", "--use-rfc2307",
                 "--realm", REALM, "--domain", NOME_NETBIOS, "--server-role=dc",
                 "--dns-backend=SAMBA_INTERNAL", "--adminpass", SENHA_ADMIN])
    # Sem TLS neste script
    tls_params = ["dns forwarder = 127.0.0.1:5353"]
    update_smb_conf(tls_params)
    print("Provisionamento concluido (sem TLS).")

def configurar_samba_e_bind():
    print("\n--- FASE 5: SAMBA E BIND ---")
    update_smb_conf(["interfaces = lo " + INTERFACE_REDE, "bind interfaces only = yes"])
    
    # Criar diretórios do BIND
    run_command(["sudo", "mkdir", "-p", "/var/cache/bind"])
    run_command(["sudo", "mkdir", "-p", "/var/lib/bind"])
    run_command(["sudo", "chown", "-R", "bind:bind", "/var/cache/bind"])
    run_command(["sudo", "chown", "-R", "bind:bind", "/var/lib/bind"])
    
    # named.conf - arquivo principal com includes
    named_conf = """// BIND configuration file for Debian 13
// Main configuration file that includes other directives

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
"""
    create_file_with_content("/etc/bind/named.conf", named_conf)

    # named.conf.options - opções globais (forwarders, allow-query, etc.)
    named_options = """options {
    directory "/var/cache/bind";
    listen-on port 5353 { 127.0.0.1; };
    listen-on-v6 { none; };
    allow-query { localhost; any; };
    recursion yes;
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    dnssec-validation no;
    auth-nxdomain no;
};
"""
    create_file_with_content("/etc/bind/named.conf.options", named_options)

    # named.conf.local - zonas locais (vazio por enquanto, Samba gerencia)
    named_local = """// Local zones configuration
// Samba AD DC manages DNS zones dynamically
"""
    create_file_with_content("/etc/bind/named.conf.local", named_local)

    # named.conf.default-zones - zonas padrão (localhost, etc.)
    named_default_zones = """// Default zones
zone "localhost" {
    type master;
    file "/etc/bind/db.local";
};

zone "127.in-addr.arpa" {
    type master;
    file "/etc/bind/db.127";
};

zone "0.in-addr.arpa" {
    type master;
    file "/etc/bind/db.0";
};

zone "255.in-addr.arpa" {
    type master;
    file "/etc/bind/db.255";
};
"""
    create_file_with_content("/etc/bind/named.conf.default-zones", named_default_zones)

    # Configurar daemon do BIND9
    bind_default = """OPTIONS="-u bind -4"
"""
    create_file_with_content("/etc/default/bind9", bind_default)
    
    print("Samba e BIND configurados.")

def integracao_final():
    print("\n--- FASE 6: INTEGRACAO ---")
    desativar_systemd_resolved()
    krb5 = "[libdefaults]\n  default_realm = " + REALM.upper() + "\n  dns_lookup_realm = false\n  dns_lookup_kdc = true\n\n[realms]\n  " + REALM.upper() + " = {\n    kdc = " + HOSTNAME_COMPLETO.lower() + "\n    admin_server = " + HOSTNAME_COMPLETO.lower() + "\n    default_domain = " + REALM.lower() + "\n  }\n\n[domain_realm]\n  ." + REALM.lower() + " = " + REALM.upper() + "\n  " + REALM.lower() + " = " + REALM.upper() + "\n"
    create_file_with_content("/etc/krb5.conf", krb5)
    
    # Iniciar serviços
    for svc in ["bind9"]:
        run_command(["sudo", "systemctl", "enable", svc])
        run_command(["sudo", "systemctl", "restart", svc])
    
    print("Iniciando Samba...")
    run_command(["sudo", "systemctl", "enable", "samba-ad-dc"])
    run_command(["sudo", "systemctl", "restart", "samba-ad-dc"])
    esperar_samba_ldap(tentativas=20, intervalo=5)
    print("Servicos iniciados.")

def atualizar_e_elevar_niveis():
    print("\n--- FASE 7: SCHEMA E NIVEIS ---")
    wait_for_enter("Modificacoes IRREVERSIVEIS. Enter para continuar.")
    update_smb_conf(["ad dc functional level = 2016"])
    run_command(["sudo", "systemctl", "restart", "samba-ad-dc"])
    run_command(["sudo", "systemctl", "stop", "samba-ad-dc"])
    run_command(["sudo", "samba-tool", "domain", "schemaupgrade", "--schema=2019"])
    run_command(["sudo", "samba-tool", "domain", "functionalprep", "--function-level=2016"])
    run_command(["sudo", "samba-tool", "domain", "level", "raise", "--domain-level=2016", "--forest-level=2016"])
    run_command(["sudo", "systemctl", "start", "samba-ad-dc"])
    run_command(["sudo", "samba-tool", "dbcheck", "--cross-ncs", "--fix", "--yes"])
    esperar_samba_ldap(tentativas=20, intervalo=5)
    print("Schema e niveis concluidos.")

def corrigir_particoes_dns():
    print("\n--- FASE 8: PARTICOES DNS ---")
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
    """Cria zona reversa e registros DNS via samba-tool dns."""
    print("\n--- FASE 9: ZONAS REVERSAS (samba-tool dns) ---")
    if not esperar_samba_ldap(tentativas=20, intervalo=5):
        print("Samba nao acessivel. Pulando.")
        return

    octetos = IP_ESTATICO.split('.')
    zona_reversa = '.'.join(reversed(octetos[:3])) + '.in-addr.arpa'
    ultimo_octeto = octetos[-1]

    print("  Zona reversa: " + zona_reversa)
    print("  PTR: " + ultimo_octeto + " -> " + HOSTNAME_COMPLETO)

    cred = ADMIN_USER + "%" + SENHA_ADMIN
    base_cmd = ["sudo", "samba-tool", "dns"]

    def run_dns(args, descricao):
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

    print("\n  [1/4] Criando zona reversa...")
    run_dns(["zonecreate", HOSTNAME_COMPLETO, zona_reversa],
            "zona " + zona_reversa)

    print("\n  [2/4] Adicionando PTR...")
    run_dns(["add", HOSTNAME_COMPLETO, zona_reversa,
             ultimo_octeto, "PTR", HOSTNAME_COMPLETO],
            ultimo_octeto + " -> " + HOSTNAME_COMPLETO)

    print("\n  [3/4] Adicionando registro A para 'ca'...")
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(),
             "ca", "A", IP_ESTATICO],
            "ca." + REALM.lower() + " -> " + IP_ESTATICO)

    print("\n  [4/4] Adicionando CNAME 'pki' -> ca...")
    run_dns(["add", HOSTNAME_COMPLETO, REALM.lower(),
             "pki", "CNAME", "ca." + REALM.lower()],
            "pki." + REALM.lower() + " -> ca." + REALM.lower())

    print("\n  Validando registros DNS (5s para propagacao)...")
    time.sleep(5)

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
    print(" Samba AD DC - Debian 13 (Sem SSL/TLS)")
    print(" Config: " + ENV_FILE)
    print(" AppArmor: modo complain | BIND9: estrutura modular")
    print("=" * 70)
    wait_for_enter("Enter para iniciar...")
    try:
        limpeza_previa()
        preparacao_sistema()
        configurar_iptables()
        configurar_apparmor()
        configurar_ntp()
        provisionar_dominio()
        configurar_samba_e_bind()
        integracao_final()
        atualizar_e_elevar_niveis()
        corrigir_particoes_dns()
        configurar_zonas_reversas()
        print("\n" + "=" * 70)
        print("SUCESSO! Domain Controller configurado.")
        print("  Schema 2019 | Niveis 2016 | SEM TLS")
        print("  AppArmor: modo complain | BIND9: modular")
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
