#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Script final e revisado para automatizar a instalação e configuração de um
Samba Active Directory Domain Controller no Fedora, com todas as etapas de
atualização e correção.
"""
import os
import subprocess
import sys
import time
import textwrap

# --- CARREGAR VARIÁVEIS DE AMBIENTE DO auth.env ---
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
    
    # Variáveis obrigatórias (sem CERT_PWD pois este script não usa SSL)
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
SENHA_ADMIN = CFG["SENHA_ADMIN"]

print("Config carregada de: " + ENV_FILE)
print("  HOSTNAME: " + HOSTNAME_COMPLETO + " | REALM: " + REALM)

# --- Funções Auxiliares ---

def run_command(command, shell=False, check=True):
    """Executa um comando no sistema."""
    try:
        cmd_str = command if isinstance(command, str) else ' '.join(command)
        print(f"🚀 Executando: {cmd_str}")
        subprocess.run(command, shell=shell, check=check, text=True, stdout=sys.stdout, stderr=sys.stderr)
        print("-" * 40)
        time.sleep(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ ERRO ao executar comando: {e}")
        print("A operação foi interrompida.")
        raise e

def wait_for_enter(prompt="Pressione Enter para continuar..."):
    """Pausa a execução."""
    input(f"\n👉 {prompt}")

def create_file_with_content(filepath, content):
    """Cria um arquivo com o conteúdo especificado."""
    print(f"📝 Criando/Sobrescrevendo o arquivo: {filepath}")
    try:
        temp_filepath = f"/tmp/{os.path.basename(filepath)}.tmp"
        with open(temp_filepath, "w") as f:
            f.write(content)
        run_command(["sudo", "mv", temp_filepath, filepath])
        run_command(["sudo", "restorecon", filepath], check=False)
        print(f"✅ Arquivo {filepath} criado com sucesso.")
    except IOError as e:
        print(f"❌ ERRO ao escrever no arquivo {filepath}: {e}")
        sys.exit(1)

def update_smb_conf(params_to_add):
    """Atualiza a seção [global] do smb.conf de forma segura."""
    print("🔧 Atualizando /etc/samba/smb.conf...")
    smb_conf_path = "/etc/samba/smb.conf"
    with open(smb_conf_path, 'r') as f:
        lines = f.readlines()

    param_keys = [p.split('=')[0].strip() for p in params_to_add]
    new_lines = []
    in_global_section = False
    global_section_ended = False
    params_inserted = False

    for line in lines:
        stripped_line = line.strip()
        if stripped_line.lower() == '[global]':
            in_global_section = True
            new_lines.append(line)
            continue
        elif in_global_section and stripped_line.startswith('['):
            in_global_section = False
            global_section_ended = True

        if in_global_section:
            current_key = stripped_line.split('=')[0].strip()
            if any(key_to_check == current_key for key_to_check in param_keys):
                print(f"   - Removendo linha antiga/duplicada: {stripped_line}")
                continue

        if global_section_ended and not params_inserted:
            print("   + Adicionando novas configurações na seção [global]")
            for param in params_to_add:
                new_lines.append(f"\t{param}\n")
            params_inserted = True

        new_lines.append(line)

    if in_global_section and not params_inserted:
        print("   + Adicionando novas configurações no final da seção [global]")
        for param in params_to_add:
            new_lines.append(f"\t{param}\n")

    create_file_with_content(smb_conf_path, "".join(new_lines))


# --- Funções do Script ---

def limpeza_previa():
    """Para e remove configurações e dados de instalações anteriores."""
    print("\n--- FASE 0: LIMPANDO INSTALAÇÃO ANTERIOR ---")
    wait_for_enter("AVISO: A próxima etapa removerá dados e configurações existentes.")
    servicos = ["samba", "named", "chronyd"]
    for servico in servicos:
        run_command(["sudo", "systemctl", "stop", servico], check=False)

    locais_para_limpar = [
        "/etc/samba/smb.conf", "/etc/krb5.conf", "/etc/named.conf", "/etc/chrony.conf",
        "/var/lib/samba/*", "/var/cache/samba/*", "/var/log/samba/*", "/var/named/*"
    ]
    for local in locais_para_limpar:
        print(f"Removendo {local}...")
        run_command(f"sudo rm -rf {local}", shell=True, check=False)
    print("✅ Limpeza concluída.")

def preparacao_sistema_fedora():
    """Configura o sistema base e instala os pacotes."""
    print("\n--- FASE 1: PREPARAÇÃO E INSTALAÇÃO ---")
    run_command(["sudo", "hostnamectl", "set-hostname", HOSTNAME_COMPLETO])
    hosts_content = f"127.0.0.1   localhost\n{IP_ESTATICO}   {HOSTNAME_COMPLETO}   {HOSTNAME_COMPLETO.split('.')[0]}\n"
    create_file_with_content("/etc/hosts", hosts_content)

    run_command(["sudo", "systemctl", "stop", "firewalld"], check=False)
    run_command(["sudo", "systemctl", "disable", "firewalld"], check=False)

    packages = ["samba-dc", "samba-client", "bind", "chrony", "iptables-services", "patch", "python3-markdown"]
    run_command(["sudo", "dnf", "install", "-y"] + packages)
    print("✅ Preparação do sistema concluída.")

def configurar_iptables_fedora():
    """Configura o iptables."""
    print("\n--- FASE 2: CONFIGURANDO O IPTABLES ---")
    run_command(["sudo", "iptables", "-F"])

    ports = {
        'tcp': [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5353, 1433, 1521, '49152:65535'],
        'udp': [53, 88, 123, 137, 138, 389, 464, 1433, 1521, '49152:65535']
    }
    for proto, port_list in ports.items():
        for port in port_list:
            run_command(["sudo", "iptables", "-A", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])

    run_command(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_command(["sudo", "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_command("sudo sh -c 'iptables-save > /etc/sysconfig/iptables'", shell=True)
    run_command(["sudo", "systemctl", "enable", "iptables"])
    run_command(["sudo", "systemctl", "restart", "iptables"])
    print("✅ Iptables configurado.")

def configurar_ntp_fedora():
    """Configura o NTP (Chrony)."""
    print("\n--- FASE 3: CONFIGURANDO NTP (CHRONY) ---")
    chrony_conf_content = textwrap.dedent("""
        pool 2.br.pool.ntp.org iburst
        driftfile /var/lib/chrony/drift
        makestep 1.0 3
        rtcsync
        local stratum 10
        ntpsigndsocket /var/lib/samba/ntp_signd
    """)
    create_file_with_content("/etc/chrony.conf", chrony_conf_content)
    run_command(["sudo", "install", "-d", "-o", "root", "-g", "chrony", "-m", "750", "/var/lib/samba/ntp_signd"])
    print("✅ Configuração NTP concluída.")

def provisionar_dominio():
    """Executa o provisionamento do domínio."""
    print("\n--- FASE 4: PROVISIONANDO O DOMÍNIO ---")
    provision_command = [
        "sudo", "samba-tool", "domain", "provision", "--use-rfc2307",
        "--realm", REALM, "--domain", NOME_NETBIOS, "--server-role=dc",
        "--dns-backend=SAMBA_INTERNAL", "--adminpass", SENHA_ADMIN
    ]
    run_command(provision_command)
    print("✅ Provisionamento do domínio concluído.")

def configurar_samba_e_bind():
    """Configura o smb.conf e o BIND."""
    print("\n--- FASE 5: CONFIGURANDO SAMBA E BIND ---")
    smb_params = [
        f"dns forwarder = 127.0.0.1:5353",
        f"interfaces = lo {INTERFACE_REDE}",
        f"bind interfaces only = yes"
    ]
    update_smb_conf(smb_params)

    run_command(["sudo", "mkdir", "-p", "/var/named/data"])
    run_command(["sudo", "chown", "-R", "named:named", "/var/named"])

    named_conf_content = textwrap.dedent("""
        options {
            directory "/var/named";
            listen-on port 5353 { 127.0.0.1; };
            listen-on-v6 { none; };
            allow-query { localhost; };
            recursion yes;
            forwarders { 8.8.8.8; 1.1.1.1; };
            dnssec-validation no;
        };
        logging {
            channel default_debug { file "data/named.run"; severity dynamic; };
        };
    """)
    create_file_with_content("/etc/named.conf", named_conf_content)
    create_file_with_content("/etc/sysconfig/named", 'OPTIONS="-4"')
    print("✅ Configuração do Samba e BIND concluída.")

def integracao_final():
    """Realiza a integração final, gerando um krb5.conf robusto e inicializando os serviços."""
    print("\n--- FASE 6: INTEGRAÇÃO FINAL E INICIALIZAÇÃO ---")

    # MODIFICAÇÃO: Gerar um arquivo krb5.conf completo em vez de copiar o antigo.
    print("Gerando arquivo de configuração Kerberos (/etc/krb5.conf) robusto...")
    krb5_conf_content = textwrap.dedent(f"""
[libdefaults]
    default_realm = {REALM.upper()}
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    {REALM.upper()} = {{
        kdc = {HOSTNAME_COMPLETO.lower()}
        admin_server = {HOSTNAME_COMPLETO.lower()}
        default_domain = {REALM.lower()}
    }}

[domain_realm]
    .{REALM.lower()} = {REALM.upper()}
    {REALM.lower()} = {REALM.upper()}
""")
    create_file_with_content("/etc/krb5.conf", krb5_conf_content)

    # Configuração do resolv.conf
    resolv_content = f"search {REALM.lower()}\nnameserver 127.0.0.1\n#nameserver 1.1.1.1\n"
    run_command(["sudo", "chattr", "-i", "/etc/resolv.conf"], check=False)
    create_file_with_content("/etc/resolv.conf", resolv_content)
    run_command(["sudo", "chattr", "+i", "/etc/resolv.conf"], check=False)

    # Inicialização dos serviços
    services = ["chronyd", "named", "samba"]
    for service in services:
        print(f"Habilitando e reiniciando o serviço: {service}")
        run_command(["sudo", "systemctl", "enable", service])
        run_command(["sudo", "systemctl", "restart", service])
    print("✅ Servidor pronto e serviços iniciados.")

def atualizar_e_elevar_niveis():
    """Atualiza schema e eleva níveis funcionais seguindo o fluxo especificado pelo usuário."""
    print("\n--- FASE 7: ATUALIZANDO SCHEMA E NÍVEIS FUNCIONAIS ---")

    warning = textwrap.dedent("""
        AVISO: A próxima etapa realizará modificações IRREVERSÍVEIS no seu
        Active Directory (atualização de schema e elevação de níveis funcionais).
    """)
    print(warning)
    wait_for_enter("Pressione Enter para confirmar e continuar, ou Ctrl+C para cancelar.")

    # Adiciona a linha (não documentada) ao smb.conf conforme solicitado
    print("Adicionando 'ad dc functional level' ao smb.conf (passo do tutorial)...")
    update_smb_conf(["ad dc functional level = 2016"])

    print("Reiniciando o serviço Samba...")
    run_command(["sudo", "systemctl", "restart", "samba"])

    print("Parando o serviço Samba para realizar as atualizações...")
    run_command(["sudo", "systemctl", "stop", "samba"])

    print("Atualizando o schema do domínio para 2019...")
    run_command(["sudo", "samba-tool", "domain", "schemaupgrade", "--schema=2019"])

    print("Preparando o domínio para o nível funcional 2016...")
    run_command(["sudo", "samba-tool", "domain", "functionalprep", "--function-level=2016"])

    print("Elevando os níveis de DOMÍNIO e FLORESTA para 2016...")
    run_command(["sudo", "samba-tool", "domain", "level", "raise", "--domain-level=2016", "--forest-level=2016"])

    print("Reiniciando o serviço Samba após as atualizações...")
    run_command(["sudo", "systemctl", "start", "samba"])
    print("Verificando a base de dados após a elevação...")
    run_command(["sudo", "samba-tool", "dbcheck", "--cross-ncs", "--fix", "--yes"])

    print("✅ Etapa de atualização e elevação concluída.")

# MODIFICAÇÃO: Nova função adicionada
def corrigir_particoes_dns():
    """Verifica e corrige o atributo msDS-SDReferenceDomain nas partições DNS do AD."""
    print("\n--- FASE 9: CORRIGINDO PARTIÇÕES DE DNS ---")
    wait_for_enter("O próximo passo irá verificar e corrigir um atributo importante nas zonas de DNS do AD.")

    fix_script_path = "/tmp/fix_dns_partitions.py"
    # Este script Python será criado e executado no servidor para interagir com o Samba
    fix_script_content = textwrap.dedent(f"""
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
from samba.auth import system_session
from samba.credentials import Credentials
from samba.samdb import SamDB
import optparse
import samba.getopt as options

try:
    parser = optparse.OptionParser("fix_dns_partitions.py")
    sambaopts = options.SambaOptions(parser)
    lp = sambaopts.get_loadparm()
    creds = Credentials()
    creds.guess(lp)
    samdb = SamDB(session_info=system_session(), credentials=creds, lp=lp)

    domain_dn = samdb.get_default_basedn()
    domain_name = lp.get('realm').lower()
    partitions_dn = "CN=Partitions," + str(samdb.get_config_basedn())
    search_filter = f"(|(dnsRoot=DomainDnsZones.{{domain_name}})(dnsRoot=ForestDnsZones.{{domain_name}}))"

    print(f"Verificando partições DNS para o domínio {{domain_name}}...")
    partitions = samdb.search(base=partitions_dn, expression=search_filter, scope=1)

    for p in partitions:
        if 'msDS-SDReferenceDomain' not in p:
            print(f"  -> Corrigindo partição: {{p['dn']}}")
            # Constrói o LDIF com newlines para garantir a formatação correta
            ldif_data = (
                f"dn: {{p['dn']}}\\n"
                f"changetype: modify\\n"
                f"replace: msDS-SDReferenceDomain\\n"
                f"msDS-SDReferenceDomain: {{str(domain_dn)}}\\n"
            )
            # MODIFICAÇÃO: Removido o .encode('utf-8')
            samdb.modify_ldif(ldif_data)
            print(f"     ... Atributo 'msDS-SDReferenceDomain' adicionado com sucesso.")
        else:
            print(f"  -> Partição já está correta: {{p['dn']}}")

    print("Verificação e correção concluídas.")
    sys.exit(0)
except Exception as e:
    print(f"Ocorreu um erro ao corrigir partições: {{e}}")
    sys.exit(1)
    """)
    create_file_with_content(fix_script_path, fix_script_content)
    run_command(["sudo", "python3", fix_script_path])
    run_command(["sudo", "rm", "-f", fix_script_path])
    print("✅ Correção das partições de DNS concluída.")

def main():
    """Função principal que orquestra toda a instalação."""
    if os.geteuid() != 0:
        print("\n❌ ERRO: Este script precisa ser executado como root ou com 'sudo'.")
        sys.exit(1)

    clear = lambda: os.system('clear')
    clear()
    print("======================================================")
    print(" Script Final de Instalação e Atualização do Samba AD DC")
    print("======================================================")
    wait_for_enter()

    try:
        limpeza_previa()
        preparacao_sistema_fedora()
        configurar_iptables_fedora()
        configurar_ntp_fedora()
        provisionar_dominio()
        configurar_samba_e_bind()
        integracao_final()

        print("\n🎉 Verificando status pós-instalação...")
        run_command(["sudo", "systemctl", "status", "samba", "named", "chronyd", "--no-pager"], check=False)

        atualizar_e_elevar_niveis()

        # MODIFICAÇÃO: Chamada da nova função de correção
        corrigir_particoes_dns()

        print("\n======================================================")
        print("✅ SUCESSO! Seu Domain Controller foi configurado e otimizado.")
        print("Schema: 2019, Níveis Funcionais: 2016, Partições DNS: Corrigidas.")
        print("======================================================")

    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a instalação: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
