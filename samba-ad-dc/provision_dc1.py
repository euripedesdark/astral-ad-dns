#!/usr/bin/env python3
"""DC1 provisioning stack: one implementation, JSON input from the web console.
No project-local Python modules are required by this script.
"""


# ad_operations.py — integrated implementation
import argparse


import fcntl


import ipaddress


import json


import os


from pathlib import Path, PurePosixPath


import re


import shlex


import shutil


import subprocess


import sys


import tarfile


import tempfile


import uuid


import time


class OperationError(RuntimeError):
    pass


def checked_run(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=1800)
    if result.returncode:
        raise OperationError(f"{args[0]} falhou: {(result.stderr or result.stdout)[-3000:]}")
    return result.stdout


def local_ipv4s(run=None):
    """IPv4 globais da maquina, sem depender de 'hostname -I' (inexistente em inetutils/Arch)."""
    runner = run or checked_run
    output = runner(['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'])
    if not isinstance(output, str):
        output = str(output)
    return re.findall(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/', output)


def atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.astral-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as file:
            file.write(text.encode() if isinstance(text, str) else text)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def bind_paths(root):
    if (root / 'etc/bind').is_dir() or (root / 'etc/debian_version').exists():
        return root / 'etc/bind/named.conf.options', root / 'etc/bind/named.conf', 'bind9', '/var/cache/bind'
    return root / 'etc/named.conf', root / 'etc/named.conf', 'named', '/var/named'


def normalize_forwarders(values):
    output = []
    for value in values:
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError as error:
            raise OperationError('Forwarder deve ser um endereço IPv4 ou IPv6.') from error
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise OperationError('Forwarder não pode criar loop local ou usar multicast/link-local.')
        if str(ip) not in output:
            output.append(str(ip))
    if not output:
        raise OperationError('Informe pelo menos um forwarder externo ao resolvedor local.')
    return output


def hybrid_options(forwarders, directory):
    return ('options {\n'
            f'    directory "{directory}";\n'
            '    listen-on port 5353 { 127.0.0.1; };\n'
            '    listen-on-v6 { none; };\n'
            '    allow-query { localhost; };\n'
            '    allow-recursion { localhost; };\n'
            '    allow-query-cache { localhost; };\n'
            '    recursion yes;\n'
            '    forward only;\n'
            '    forwarders { ' + ' '.join(ip + ';' for ip in forwarders) + ' };\n'
            '    dnssec-validation auto;\n'
            '    max-cache-size 64m;\n'
            '    minimal-responses yes;\n'
            '};\n')


def replace_options(content, options):
    # Comments/strings must not affect brace depth or match a fake options clause.
    clean = re.sub(r'//[^\n]*|#[^\n]*|/\*.*?\*/', lambda m: ' ' * len(m[0]), content, flags=re.S)
    if re.search(r'\bdlz\s*["{]|bind-dns/named\.conf', clean, re.I):
        raise OperationError('Configuração DLZ encontrada. Migre-a separadamente antes de ativar o BIND recursivo.')
    match = re.search(r'\boptions\s*\{', clean)
    if not match:
        if re.search(r'\binclude\b', clean):
            raise OperationError('Bloco options está em outro arquivo; selecione a configuração da distribuição.')
        return content + '\n' + options
    level = 1
    quoted = False
    escaped = False
    for index in range(match.end(), len(clean)):
        char = clean[index]
        if escaped:
            escaped = False
        elif char == '\\' and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            level += (char == '{') - (char == '}')
            if level == 0:
                end = index + 1
                while end < len(clean) and clean[end].isspace():
                    end += 1
                if end >= len(clean) or clean[end] != ';':
                    raise OperationError('Bloco options inválido.')
                return content[:match.start()] + options.rstrip() + content[end + 1:]
    raise OperationError('Bloco options incompleto.')


def check_bind_runtime(root, main, service, run):
    # A successful restart does not prove that the daemon loaded the file we edited.
    expected = '/' + str(main.relative_to(root))
    sysconfig = root / 'etc/sysconfig/named'
    if sysconfig.exists():
        for line in sysconfig.read_text().splitlines():
            match = re.match(r'^\s*(?:export\s+)?NAMEDCONF\s*=\s*(.*)$', line)
            if match:
                words = shlex.split(match[1], comments=True)
                configured = ' '.join(words)
                if configured and configured != expected:
                    raise OperationError(f'NAMEDCONF aponta para {configured}, mas o configurador selecionou {expected}; configuracao preservada.')
    pid = run(['systemctl', 'show', service, '-p', 'MainPID', '--value']).strip()
    command = root / 'proc' / pid / 'cmdline' if pid.isdigit() and int(pid) else None
    if command and command.is_file():
        args = [part.decode() for part in command.read_bytes().split(b'\0') if part]
        if '-t' in args:
            raise OperationError('BIND esta em chroot; a configuracao desse ambiente deve ser selecionada antes de alterar named.conf.')
        if '-c' in args:
            configured = args[args.index('-c') + 1]
            expected = '/' + str(main.relative_to(root))
            if configured != expected:
                raise OperationError(f'O named ativo usa {configured}, mas o configurador selecionou {expected}; nenhum arquivo foi alterado.')
    # BIND binds only IPv4 127.0.0.1. A multicast socket (Chrome mDNS,
    # e.g. 224.0.0.251:5353) does not occupy that local address.
    # Keep wildcard and loopback conflicts protected; never stop their owners.
    listeners = run(['ss', '-H', '-lntup', '( sport = :5353 )'])
    for line in listeners.splitlines():
        if not line.strip() or re.search(r'"named(?:-sdb)?"', line):
            continue
        fields = line.split()
        if len(fields) < 5:
            raise OperationError('Nao foi possivel identificar o endereco local do listener 5353: ' + line)
        address = fields[4].rsplit(':', 1)[0].strip('[]').split('%', 1)[0]
        if address not in ['*', '0.0.0.0', '::', '127.0.0.1']:
            try:
                parsed = ipaddress.ip_address(address)
                if parsed != ipaddress.ip_address('::ffff:127.0.0.1'):
                    continue
            except ValueError:
                raise OperationError('Endereco do listener 5353 nao reconhecido: ' + line)
        raise OperationError('Endereco local 127.0.0.1:5353 ou wildcard ocupado por outro processo; nenhum servico foi parado: ' + line)


def port_labels(output, protocol):
    labels = []
    for line in output.splitlines():
        match = re.match(r'^(\w+_port_t)\s+(tcp|udp)\s+(.+)$', line.strip())
        if not match or match[2] != protocol:
            continue
        for item in match[3].split(','):
            item = item.strip()
            if item == '5353':
                labels.append(match[1])
    return labels


def prepare_bind_selinux(root, run, undo):
    if not (root / 'sys/fs/selinux/enforce').exists():
        return []
    if not shutil.which('semanage'):
        raise OperationError('SELinux ativo: instale policycoreutils-python-utils (dnf install policycoreutils-python-utils) para autorizar o BIND na porta 5353. SELinux foi preservado.')
    labels = run(['semanage', 'port', '-l'])
    local = run(['semanage', 'port', '-l', '-C'])
    steps = []
    for protocol in ['tcp', 'udp']:
        previous = port_labels(labels, protocol)
        if previous == ['dns_port_t']:
            continue
        if len(previous) > 1:
            raise OperationError('Politica SELinux ambigua para ' + protocol + '/5353; nenhuma politica global sera substituida.')
        local_previous = port_labels(local, protocol)
        action = '-m' if previous else '-a'
        run(['semanage', 'port', action, '-t', 'dns_port_t', '-p', protocol, '5353'])
        # Removing a new local override restores the distribution policy (including mDNS).
        undo.append(['semanage', 'port', '-m', '-t', local_previous[0], '-p', protocol, '5353']
                    if local_previous else ['semanage', 'port', '-d', '-p', protocol, '5353'])
        steps.append('SELinux: ' + protocol + '/5353 autorizado como dns_port_t para o BIND.')
    return steps


def wait_bind_ready(run, service, attempts=6):
    """Wait for the local recursive listener, separately from AD discovery on :53."""
    last_error = 'listener ainda indisponivel'
    for attempt in range(attempts):
        try:
            for transport in [[], ['+tcp']]:
                reply = run(['dig', '@127.0.0.1', '-p', '5353', '.', 'SOA', '+tries=1', '+time=1'] + transport)
                if 'status: NOERROR' not in reply:
                    raise OperationError('BIND respondeu sem NOERROR: ' + reply[-400:])
            return
        except OperationError as error:
            last_error = str(error)
            if attempt + 1 < attempts:
                time.sleep(0.25)
    details = []
    for command in [
        ['systemctl', 'show', service, '-p', 'ActiveState', '-p', 'SubState', '-p', 'ExecStart'],
        ['journalctl', '-u', service, '-n', '80', '--no-pager'],
        ['ss', '-H', '-lntup', '( sport = :5353 )'],
        ['getenforce'],
        ['ausearch', '-m', 'AVC,USER_AVC', '-ts', 'recent', '-c', 'named'],
    ]:
        try:
            output = run(command)
            if command[0] == 'journalctl':
                important = [line for line in output.splitlines() if re.search(r'denied|permission|listen|bind|address|error|failed', line, re.I)]
                output = '\n'.join(important) or output
            details.append(output[-1800:])
        except (OperationError, OSError):
            pass
    raise OperationError('BIND recursivo LOCAL nao respondeu em TCP/UDP 127.0.0.1:5353; '
                         'este teste nao e o ingresso nem o DNS do DC parceiro na porta 53. '
                         + last_error + ('; diagnostico: ' + ' '.join(details) if any(details) else ''))


def configure_bind(request, root=Path('/'), run=checked_run):
    forwarders = normalize_forwarders(request.get('forwarders', []))
    package_steps = []
    if root == Path('/') and not request.get('dry_run'):
        install_dependencies(root,run,True,package_steps,required_commands=['named','named-checkconf','dig','ip','semanage'])
    config, main, service, directory = bind_paths(root)
    original_stat = config.stat() if config.exists() else None
    original = config.read_bytes() if config.exists() else None
    candidate = replace_options(original.decode() if original else '', hybrid_options(forwarders, directory))
    if request.get('dry_run'):
        return ['Plano BIND: TCP/UDP 127.0.0.1:5353, ACL localhost, forward only, DNSSEC e cache 64 MiB.',
                'Forwarders validados: ' + ', '.join(forwarders),
                'Nenhuma configuração ou serviço foi alterado.']
    config.parent.mkdir(parents=True, exist_ok=True)
    staged = config.with_name('.astral-named-' + uuid.uuid4().hex)
    backup = config.with_name(config.name + '.pre-astral-' + uuid.uuid4().hex)
    was_active = False
    installed = False
    selinux_undo = []
    selinux_steps = []
    try:
        check_bind_runtime(root, main, service, run)
        # named runs unprivileged on Arch: do not inherit an unreadable
        # root-only configuration mode from a previous deployment.
        atomic_write(staged, candidate, 0o640)
        run(['chown', 'root:' + ('bind' if service == 'bind9' else 'named'), str(staged)])
        run(['named-checkconf', str(staged)])
        try:
            was_active = run(['systemctl', 'is-active', service]).strip() == 'active'
        except OperationError:
            pass
        if original is not None:
            shutil.copy2(config, backup)
            os.chown(backup, original_stat.st_uid, original_stat.st_gid)
        os.replace(staged, config)
        installed = True
        run(['named-checkconf', str(main)])
        if shutil.which('restorecon') and root == Path('/'):
            run(['restorecon', str(config)])
        selinux_steps = prepare_bind_selinux(root, run, selinux_undo)
        run(['systemctl', 'restart', service])
        wait_bind_ready(run, service)
        run(['systemctl', 'enable', service])
        return package_steps + selinux_steps + [f'BIND {service} validado e ativo em 127.0.0.1:5353.',
                'Forwarders: ' + ', '.join(forwarders), f'Configuração anterior: {backup}' if original is not None else 'Nova configuração criada.']
    except Exception as error:
        rollback_errors = []
        for command in reversed(selinux_undo):
            try:
                run(command)
            except Exception as failure:
                rollback_errors.append('SELinux: ' + str(failure))
        if installed:
            try:
                if original is None:
                    config.unlink(missing_ok=True)
                else:
                    os.replace(backup, config)
                if was_active:
                    run(['systemctl', 'restart', service])
                else:
                    run(['systemctl', 'stop', service])
            except Exception as failure:
                rollback_errors.append(str(failure))
        suffix = '; rollback falhou: ' + '; '.join(rollback_errors) if rollback_errors else '; configuração anterior preservada/restaurada'
        raise OperationError(str(error) + suffix) from error
    finally:
        staged.unlink(missing_ok=True)



# provision_system.py — integrated implementation
"""Distro-aware preparation, non-destructive firewall and signed NTP for web jobs."""


import json


from pathlib import Path


import re


import shutil


import socket


import itertools


TOOLS = {
 'samba-tool': ['samba-tools','samba-common-bin','samba','samba'],
 'samba': ['samba-dc','samba-ad-dc','samba','samba-ad-dc'],
 'testparm': ['samba-common-tools','samba-common-bin','samba','samba-client'],
 'smbclient': ['samba-client','smbclient','smbclient','samba-client'],
 'net': ['samba-common-tools','samba-common-bin','samba','samba-client'],
 'winbindd': ['samba-winbind','winbind','samba','samba-winbind'],
 'dig': ['bind-utils','dnsutils','bind','bind-utils'],
 'ip': ['iproute','iproute2','iproute2','iproute2'],
 'iptables': ['iptables','iptables','iptables','iptables'],
 'iptables-save': ['iptables','iptables','iptables','iptables'],
 'chronyd': ['chrony','chrony','chrony','chrony'],
 'openssl': ['openssl','openssl','openssl','openssl'],
 'curl': ['curl','curl','curl','curl'],
 'named': ['bind','bind9','bind','bind'],
 'named-checkconf': ['bind','bind9-utils','bind','bind-utils'],
 'semanage': ['policycoreutils-python-utils','policycoreutils-python-utils','policycoreutils','policycoreutils-python-utils'],
}


def install_dependencies(root, run, bind, steps, required_commands=None):
    managers = [('dnf',0),('yum',0),('apt-get',1),('pacman',2),('zypper',3)]
    selected = next(((name,index) for name,index in managers if shutil.which(name)), None)
    commands = list(required_commands) if required_commands else [name for name in TOOLS if name not in ['named','named-checkconf','semanage'] or bind]
    if not (root / 'sys/fs/selinux/enforce').exists() and 'semanage' in commands:
        commands.remove('semanage')
    missing = [name for name in commands if not shutil.which(name)]
    if not missing:
        return
    if not selected:
        raise OperationError('Distribuicao sem gerenciador reconhecido. Suportados: dnf/yum, apt, pacman e zypper; nenhuma base sera limpa.')
    manager,index = selected
    packages = sorted({TOOLS[name][index] for name in missing})
    policy = root / 'usr/sbin/policy-rc.d'
    saved = policy.read_bytes() if policy.exists() else None
    saved_mode = policy.stat().st_mode & 0o777 if policy.exists() else 0o755
    try:
        if manager == 'apt-get':
            atomic_write(policy, '#!/bin/sh\nexit 101\n', 0o755)
            run([manager,'update'])
            command = ['env','DEBIAN_FRONTEND=noninteractive',manager,'install','-y']
        elif manager == 'pacman':
            command = [manager,'-S','--needed','--noconfirm']
        elif manager == 'zypper':
            command = [manager,'--non-interactive','install']
        else:
            command = [manager,'install','-y']
        run(command + packages)
    finally:
        if manager == 'apt-get':
            if saved is None:
                policy.unlink(missing_ok=True)
            else:
                atomic_write(policy,saved,saved_mode)
    remaining = [name for name in commands if not shutil.which(name)]
    if remaining:
        raise OperationError('A distribuicao/pacotes instalados nao disponibilizaram: ' + ', '.join(remaining) + '. Nenhum ingresso/limpeza foi iniciado.')
    steps.append('Dependencias instaladas pela interface (' + manager + '): ' + ', '.join(packages))


def allocate_ca_port(root,run,preferred=8443):
    used=set()
    for line in run(['ss','-H','-lntup']).splitlines():
        fields=line.split()
        if len(fields)>4:
            port=fields[4].rsplit(':',1)[-1]
            if port.isdigit(): used.add(int(port))
    attempted=set()
    for port in itertools.chain([preferred,9443,10443],range(10444,65536)):
        if port in attempted or port in used: continue
        attempted.add(port)
        if root==Path('/'):
            try:
                for transport in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
                    with socket.socket(socket.AF_INET,transport) as probe: probe.bind(('0.0.0.0',port))
            except OSError: continue
        return port
    raise OperationError('Nao foi encontrada uma porta TCP/UDP livre para a nova CA; nenhum servico foi substituido.')


def firewall_rules(role, step_ca=False, ca_port=9443):
    tcp = [53,88,135,139,389,445,464,636,8095]
    udp = [53,88,123,137,138,389,464]
    if role != 'MEMBER':
        tcp += [3268,3269]
    if step_ca:
        tcp.append(ca_port)
        udp.append(ca_port)
    rules = [['-i','lo','-j','ACCEPT'], ['-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']]
    for protocol,ports in [('tcp',tcp),('udp',udp)]:
        rules += [['-p',protocol,'--dport',str(port),'-j','ACCEPT'] for port in ports]
    rules.append(['-p','tcp','--dport','49152:65535','-j','ACCEPT'])
    return rules


RESTORE_SCRIPT = '''#!/usr/bin/python3
import json, subprocess
from pathlib import Path
rules=json.loads(Path('/etc/astral-ad-dns/provision-firewall.json').read_text())
chain=subprocess.run(['iptables','-S','INPUT'],capture_output=True,text=True,check=True).stdout
first=next((line for line in chain.splitlines() if line.startswith('-A INPUT ')), '')
position='2' if first.strip()=='-A INPUT -j ts-input' else '1'
for rule in rules:
    if subprocess.run(['iptables','-C','INPUT',*rule],capture_output=True).returncode:
        subprocess.run(['iptables','-I','INPUT',position,*rule],check=True)
'''


def configure_firewall(request, root, backup, run, steps):
    atomic_write(backup / 'iptables-before.rules',run(['iptables-save']))
    rules = firewall_rules(request['domain_role'],request.get('initialize_ca',False),int(request.get('ca_port',9443)))
    added = 0
    chain=run(['iptables','-S','INPUT'])
    first=next((line for line in chain.splitlines() if line.startswith('-A INPUT ')), '')
    position='2' if first.strip()=='-A INPUT -j ts-input' else '1'
    for rule in rules:
        try:
            run(['iptables','-C','INPUT'] + rule)
        except OperationError:
            run(['iptables','-I','INPUT',position] + rule)
            added += 1
    # Fedora and Ubuntu may have another manager with a later DROP hook.
    # Open the same required ports there without deleting or replacing its policy.
    try: firewalld=run(['systemctl','is-active','firewalld']).strip()=='active'
    except OperationError: firewalld=False
    if firewalld:
        active=run(['firewall-cmd','--get-active-zones'])
        zones=[line.strip() for line in active.splitlines() if line.strip() and not line[0].isspace()]
        if not zones: zones=[run(['firewall-cmd','--get-default-zone']).strip()]
        for rule in rules:
            if '--dport' not in rule: continue
            port=rule[rule.index('--dport')+1].replace(':','-')
            protocol=rule[rule.index('-p')+1]
            for zone in zones:
                for permanent in [[],['--permanent']]:
                    command=['firewall-cmd','--zone='+zone]+permanent
                    try: run(command+['--query-port='+port+'/'+protocol])
                    except OperationError: run(command+['--add-port='+port+'/'+protocol])
        steps.append('firewalld ativo: portas correspondentes tambem autorizadas nas zonas ativas, sem recarregar/apagar regras existentes.')
    try: ufw=run(['ufw','status']).startswith('Status: active')
    except (OperationError,OSError): ufw=False
    if ufw:
        for rule in rules:
            if '--dport' in rule:
                run(['ufw','allow','in','proto',rule[rule.index('-p')+1],'to','any','port',rule[rule.index('--dport')+1]])
        steps.append('UFW ativo: portas necessarias autorizadas tambem na politica persistente existente.')
    # Persist only our idempotent insertions; do not flush tables or override policies at boot.
    atomic_write(root / 'etc/astral-ad-dns/provision-firewall.json',json.dumps(rules))
    atomic_write(root / 'usr/local/lib/astral-ad-dns/firewall-restore.py',RESTORE_SCRIPT,0o700)
    atomic_write(root / 'etc/systemd/system/astral-ad-firewall.service',
        '[Unit]\nDescription=Astral AD required firewall ports\nAfter=network-pre.target firewalld.service ufw.service\nBefore=network.target\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /usr/local/lib/astral-ad-dns/firewall-restore.py\n'
        '[Install]\nWantedBy=multi-user.target\n',0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','astral-ad-firewall.service'])
    steps.append('iptables: ' + str(added) + ' regras ausentes adicionadas; portas GC 3268/3269 e RPC consideradas. Regras/politicas anteriores preservadas; persistencia automatica configurada.')


def configure_ntp(request, root, run, steps):
    member=request['domain_role']=='MEMBER'
    config = root / ('etc/chrony/chrony.conf' if (root / 'etc/chrony').is_dir() else 'etc/chrony.conf')
    text = config.read_text() if config.exists() else 'pool pool.ntp.org iburst\nmakestep 1.0 3\nrtcsync\n'
    text = re.sub(r'(?im)^\s*ntpsigndsocket\s+.*$', '', text)
    if not member: text += '\nntpsigndsocket /var/lib/samba/ntp_signd\n'
    if request.get('target_dc_ip') and request['target_dc_ip'] not in text:
        text+='server '+request['target_dc_ip']+' iburst prefer\n'
    atomic_write(config,text,0o644)
    if not member:
        group = None
        for candidate in ['chrony','_chrony']:
            try:
                if run(['getent','group',candidate]).strip():
                    group = candidate
                    break
            except OperationError:
                pass
        if not group:
            raise OperationError('Grupo de servico chrony nao encontrado apos instalar o pacote.')
        run(['install','-d','-o','root','-g',group,'-m','750',str(root / 'var/lib/samba/ntp_signd')])
    # Unit names differ between Fedora/Arch and Debian.
    for name in ['chronyd','chrony']:
        try:
            if run(['systemctl','show',name,'-p','LoadState','--value']).strip() == 'loaded':
                run(['systemctl','enable','--now',name])
                run(['systemctl','restart',name])
                steps.append(('NTP cliente configurado' if member else 'NTP assinado ntp_signd configurado')+' e chrony ativo ('+name+').')
                return
        except OperationError:
            continue
    raise OperationError('Unit chrony/chronyd indisponivel ou nao iniciou.')


def configure_identity(request, root, run, steps):
    candidates = local_ipv4s(run)
    partner = request.get('target_dc_ip')
    route = run(['ip','-4','route','get',partner]).split() if partner else []
    address = request.get('static_ip') or (route[route.index('src')+1] if 'src' in route else next((ip for ip in candidates if re.fullmatch(r'\d+\.\d+\.\d+\.\d+',ip)),''))
    import ipaddress
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError as error:
        raise OperationError('Nao foi possivel determinar o IPv4 local; selecione o IP na interface.') from error
    if str(ip) not in candidates:
        raise OperationError('O IPv4 selecionado nao esta atribuido a esta maquina; nenhuma configuracao de rede sera inventada.')
    fqdn = request.get('hostname_fqdn') or request['netbios_name'].lower()+'.'+request['realm'].lower()
    if not re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+',fqdn) or not fqdn.lower().endswith('.'+request['realm'].lower()):
        raise OperationError('FQDN deve pertencer ao dominio informado.')
    request['hostname_fqdn'],request['host_ip'] = fqdn.lower(),str(ip)
    run(['hostnamectl','set-hostname',fqdn.lower()])
    hosts = root/'etc/hosts'
    text=hosts.read_text() if hosts.exists() else '127.0.0.1 localhost\n'
    if not any(fqdn.lower() in line.lower().split() and line.split()[0]==str(ip) for line in text.splitlines() if line.strip() and not line.startswith('#')):
        text += '\n'+str(ip)+' '+fqdn.lower()+' '+fqdn.split('.')[0].lower()+'\n'
        atomic_write(hosts,text,0o644)
    steps.append('Identidade local: '+fqdn.lower()+' ('+str(ip)+'); demais entradas hosts preservadas.')


def configure_dns_records(request,run,steps):
    server=request.get('target_dc_ip') or request['host_ip']
    domain=request['realm'].lower();host=request['netbios_name'].lower();ip=request['host_ip']
    credentials=['-U'+request.get('admin_username','Administrator'),'--password='+request['admin_password']]
    octets=ip.split('.');zone='.'.join(octets[:3][::-1])+'.in-addr.arpa'
    operations=[['zonecreate',server,zone],['add',server,domain,host,'A',ip],
                ['add',server,zone,octets[3],'PTR',request['hostname_fqdn']]]
    if request['domain_role']!='MEMBER':
        operations.append(['add',server,domain,'@','NS',request['hostname_fqdn']])
    if request.get('initialize_ca'):
        operations += [['add',server,domain,'ca','A',ip],['add',server,domain,'pki','CNAME','ca.'+domain]]
    for args in operations:
        try:
            run(['samba-tool','dns']+args+credentials)
        except OperationError as error:
            if not any(code in str(error).lower() for code in ['already exists','already_exists','zone_already_exists','record_already_exists']):
                raise
    steps.append('Registros A, PTR, zona reversa /24 e NS (quando DC) verificados no DNS do dominio.')



# provision_pki.py — integrated implementation
"""Preserve existing CA; optional web-managed Step-CA and signed Samba certificate."""


import json


from pathlib import Path


import re


import shutil


import tempfile


import time


from urllib.parse import urlsplit


def step_binary():
    return shutil.which('step-cli') or shutil.which('step')


def install_step(root,run):
    if step_binary() and shutil.which('step-ca'):return
    manager=next((m for m in ['dnf','yum','apt-get','pacman','zypper'] if shutil.which(m)),None)
    if manager in ['dnf','yum']:
        repo=root/'etc/yum.repos.d/smallstep.repo'
        if not repo.exists():
            atomic_write(repo,'[smallstep]\nname=Smallstep\nbaseurl=https://packages.smallstep.com/stable/fedora/\nenabled=1\nrepo_gpgcheck=0\ngpgcheck=1\ngpgkey=https://packages.smallstep.com/keys/smallstep-0x889B19391F774443.gpg\n',0o644)
        run([manager,'install','-y','step-cli','step-ca'])
    elif manager=='apt-get':
        key=root/'etc/apt/keyrings/smallstep.asc';key.parent.mkdir(parents=True,exist_ok=True)
        run(['curl','-fsSL','https://packages.smallstep.com/keys/apt/repo-signing-key.gpg','-o',str(key)])
        atomic_write(root/'etc/apt/sources.list.d/smallstep.sources','Types: deb\nURIs: https://packages.smallstep.com/stable/debian\nSuites: debs\nComponents: main\nSigned-By: /etc/apt/keyrings/smallstep.asc\n',0o644)
        run([manager,'update']);run(['env','DEBIAN_FRONTEND=noninteractive',manager,'install','-y','step-cli','step-ca'])
    elif manager=='pacman':run([manager,'-S','--needed','--noconfirm','step-cli','step-ca'])
    elif manager=='zypper':run([manager,'--non-interactive','install','step-cli','step-ca'])
    else:raise OperationError('Gerenciador nao suportado para instalar Step-CA automaticamente.')
    if not step_binary() or not shutil.which('step-ca'):raise OperationError('Os pacotes nao disponibilizaram step/step-ca.')


def configure_pki(request,root,run,samba_unit,steps):
    if not request.get('setup_step_ca'):return []
    initialize=bool(request.get('initialize_ca'))
    if initialize and request['kind']!='new':
        raise OperationError('Uma CA nova so pode ser inicializada em novo dominio; reingresso preserva a CA existente.')
    password=request.get('cert_password','')
    if not password:raise OperationError('Informe a senha da PKI na tela, sem reutilizar automaticamente a senha do AD.')
    install_step(root,run)
    cli = step_binary()
    home=root/'etc/step-ca';ca_config=home/'config/ca.json'
    tls=root/'etc/samba/tls';tls.mkdir(parents=True,exist_ok=True,mode=0o700)
    if initialize and ca_config.exists():
        initialize = False
        steps.append('CA local existente reutilizada; raiz, chaves e politica preservadas.')
    ca_port=int(request.get('ca_port',8443))
    configured_port=ca_port
    if ca_config.exists():
        address=json.loads(ca_config.read_text()).get('address','')
        if ':' in address: configured_port=int(address.rsplit(':',1)[1])
    url=request.get('ca_url') or 'https://'+request['host_ip']+':'+str(configured_port)
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OperationError('URL da CA deve ser HTTPS, sem credenciais/query.')
    request['ca_url'],request['ca_port']=url,configured_port
    provisioner=request.get('ca_provisioner') or 'admin@'+request['realm'].lower()
    with tempfile.TemporaryDirectory(prefix='astral-pki-',dir=tls) as temp:
        secret=Path(temp)/'password';atomic_write(secret,password)
        if initialize:
            if ca_config.exists():raise OperationError('Ja existe uma CA local; sua chave/identidade nao sera substituida.')
            listeners=run(['ss','-H','-lntup','( sport = :'+str(ca_port)+' )'])
            if listeners.strip(): raise OperationError('Porta da CA '+str(ca_port)+' ocupada. Escolha outra porta na tela; Nginx e outros servicos foram preservados.')
            try: exists=run(['getent','passwd','step']).strip()
            except OperationError: exists=''
            if not exists: run(['useradd','--system','--user-group','--home-dir','/etc/step-ca','--shell','/usr/sbin/nologin','step'])
            home.mkdir(parents=True,exist_ok=True,mode=0o700)
            permanent=home/'password.txt';atomic_write(permanent,password)
            run(['env','STEPPATH='+str(home),cli,'ca','init','--name',request['realm']+' Root CA',
                 '--dns',request['hostname_fqdn'],'--dns',request['host_ip'],'--dns','ca.'+request['realm'].lower(),
                 '--address',request['host_ip']+':'+str(ca_port),'--provisioner',provisioner,'--password-file',str(permanent),'--deployment-type','standalone'])
            data=json.loads(ca_config.read_text());claims=data.setdefault('authority',{}).setdefault('claims',{})
            claims.update(maxTLSCertDuration='8760h',defaultTLSCertDuration='8760h',disableRenewal=False)
            provisioners=data['authority'].setdefault('provisioners',[])
            for existing in provisioners:
                existing.setdefault('claims',{}).update(maxTLSCertDuration='8760h',defaultTLSCertDuration='8760h',disableRenewal=False)
            if not any(item.get('type')=='ACME' for item in provisioners):
                provisioners.append({'type':'ACME','name':'dc-auto-enroll'})
            atomic_write(ca_config,json.dumps(data,indent=2),0o600)
            run(['chown','-R','step:step',str(home)])
            unit='[Unit]\nDescription=Astral Step Certificate Authority\nAfter=network-online.target\n[Service]\nUser=step\nGroup=step\nEnvironment=STEPPATH=/etc/step-ca\nWorkingDirectory=/etc/step-ca\nExecStart='+shutil.which('step-ca')+' /etc/step-ca/config/ca.json --password-file /etc/step-ca/password.txt\nRestart=on-failure\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n'
            atomic_write(root/'etc/systemd/system/step-ca.service',unit,0o644)
            run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','step-ca'])
            ca_root=home/'certs/root_ca.crt'
        elif ca_config.exists() and parsed.hostname in [request['host_ip'],request['hostname_fqdn']]:
            run(['systemctl','start','step-ca'])
            ca_root=home/'certs/root_ca.crt'
        else:
            ca_root=tls/'trusted-step-root.crt'
            fingerprint=request.get('ca_fingerprint','').replace(':','').lower()
            if not re.fullmatch('[a-f0-9]{64}',fingerprint):raise OperationError('Informe o fingerprint SHA256 da CA existente para validar o bootstrap.')
            run(['env','STEPPATH='+temp,cli,'ca','bootstrap','--ca-url',url,'--fingerprint',fingerprint])
            shutil.copy2(Path(temp)/'certs/root_ca.crt',ca_root)
        for attempt in range(15):
            try:
                run([cli,'ca','health','--ca-url',url,'--root',str(ca_root)])
                break
            except OperationError:
                if attempt==14: raise
                time.sleep(1)
        cert,key=Path(temp)/'dc.crt',Path(temp)/'dc.key'
        sans=[request['hostname_fqdn'],request['netbios_name'].lower(),request['realm'].lower(),'ldap.'+request['realm'].lower(),request['host_ip']]
        # Match the working Arch script: ca certificate uses password-file.
        # no-password/insecure belong to other Step subcommands and are not
        # required here (the issued service key is unencrypted by default).
        sans += ['_ldap._tcp.dc._msdcs.'+request['realm'].lower(), '_kerberos._tcp.dc._msdcs.'+request['realm'].lower(), '_gc._tcp.'+request['realm'].lower(), 'ca.'+request['realm'].lower(), 'pki.'+request['realm'].lower(), '127.0.0.1']
        command=[cli,'ca','certificate',request['hostname_fqdn'],str(cert),str(key),
                 '--ca-url='+url,'--root='+str(ca_root),'--provisioner='+provisioner,
                 '--password-file='+str(secret),'--kty=RSA','--size=2048',
                 '--not-after='+str(int(request.get('ca_cert_hours',8760)))+'h']
        for san in sans:command+=['--san='+san]
        run(command)
        run(['openssl','verify','-CAfile',str(ca_root),'-untrusted',str(cert),str(cert)])
        atomic_write(tls/'dc.crt',cert.read_bytes(),0o644);atomic_write(tls/'dc.key',key.read_bytes(),0o600)
        atomic_write(tls/'ca.crt',ca_root.read_bytes(),0o644)
    if shutil.which('update-ca-trust'):
        anchor=root/'etc/pki/ca-trust/source/anchors/astral-step-root.crt';atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['update-ca-trust'])
    elif shutil.which('update-ca-certificates'):
        anchor=root/'usr/local/share/ca-certificates/astral-step-root.crt';atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['update-ca-certificates'])
    elif shutil.which('trust'):
        anchor=root/'etc/ca-certificates/trust-source/anchors/astral-step-root.crt'
        atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['trust','extract-compat'])
    else:raise OperationError('Ferramenta de trust store da distribuicao nao encontrada.')
    # Renewal uses the existing certificate/key and does not regenerate the CA.
    config={'step_binary':cli,'url':url,'cert':str(tls/'dc.crt'),'key':str(tls/'dc.key'),'root':str(tls/'ca.crt'),'unit':samba_unit,'renew_before_seconds':min(604800,max(1800,int(request.get('ca_cert_hours',8760))*1200))}
    atomic_write(root/'etc/astral-ad-dns/tls-renew.json',json.dumps(config))
    script="""#!/usr/bin/python3
import json,subprocess
from pathlib import Path
c=json.loads(Path('/etc/astral-ad-dns/tls-renew.json').read_text())
if subprocess.run(['openssl','x509','-in',c['cert'],'-checkend',str(c.get('renew_before_seconds',604800)),'-noout'],capture_output=True).returncode:
    subprocess.run([c.get('step_binary','step'),'ca','renew',c['cert'],c['key'],'--ca-url',c['url'],'--root',c['root'],'--force'],check=True)
    subprocess.run(['systemctl','restart',c['unit']],check=True)
"""
    atomic_write(root/'usr/local/lib/astral-ad-dns/tls-renew.py',script,0o700)
    atomic_write(root/'etc/systemd/system/astral-ad-tls-renew.service','[Unit]\nDescription=Astral Samba TLS renewal\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/lib/astral-ad-dns/tls-renew.py\n',0o644)
    atomic_write(root/'etc/systemd/system/astral-ad-tls-renew.timer','[Unit]\nDescription=Astral Samba TLS renewal timer\n[Timer]\nOnCalendar=*-*-* *:00/15:00\nPersistent=true\nRandomizedDelaySec=120\n[Install]\nWantedBy=timers.target\n',0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','astral-ad-tls-renew.timer'])
    steps.append('Certificado LDAPS assinado, cadeia validada, trust store e renovacao automatica configurados; CA anterior preservada.')
    return [('tls enabled','yes'),('tls keyfile',str(tls/'dc.key')),('tls certfile',str(tls/'dc.crt')),('tls cafile',str(tls/'ca.crt'))]



# provision_tls.py — integrated implementation
"""Existing host TLS material, independent from Step-CA enrollment."""


from pathlib import Path


def prepare_existing_tls(request, root, run, steps):
    mode = request.get('tls_mode', 'auto')
    if mode not in ['auto', 'existing', 'step-ca']:
        raise OperationError('Modo TLS invalido.')
    if mode == 'step-ca' or request.get('setup_step_ca'):
        if mode == 'existing':
            raise OperationError('Escolha certificados existentes ou emissao Step-CA.')
        return
    supplied = [request.get('tls_cert_path'), request.get('tls_key_path'), request.get('tls_ca_path')]
    if mode == 'existing' and not all(supplied):
        raise OperationError('Informe caminhos no servidor para certificado deste DC, chave privada e cadeia CA antes do ingresso.')
    if not any(supplied):
        # Only discover complete, conventional Samba sets. Never reuse a
        # partner DC private key or scan arbitrary filesystem directories.
        for directory, names in [('etc/samba/tls', ('dc.crt','dc.key','ca.crt')),
                                 ('var/lib/samba/private/tls', ('cert.pem','key.pem','ca.pem'))]:
            paths = [root/directory/name for name in names]
            if all(path.is_file() for path in paths):
                supplied = [str(path) for path in paths]
                break
        else:
            steps.append('TLS: nenhum conjunto existente encontrado; ingresso nativo nao exige Step-CA. Para LDAPS com CA confiavel, indique os certificados na interface.')
            return
    if not all(supplied):
        raise OperationError('Conjunto TLS incompleto; informe certificado, chave e cadeia CA na interface.')
    paths = [Path(value) for value in supplied]
    if not all(path.is_absolute() and path.is_file() for path in paths):
        raise OperationError('Arquivos TLS devem existir em caminhos absolutos no servidor.')
    cert, key, ca = map(str, paths)
    fqdn = request.get('hostname_fqdn') or request['netbios_name'].lower()+'.'+request['realm'].lower()
    try:
        run(['openssl','x509','-in',cert,'-noout','-checkend','0'])
        run(['openssl','verify','-purpose','sslserver','-verify_hostname',fqdn,'-CAfile',ca,cert])
        public_cert = run(['openssl','x509','-in',cert,'-pubkey','-noout']).strip()
        public_key = run(['openssl','pkey','-in',key,'-passin','pass:','-pubout']).strip()
        if not public_cert or public_cert != public_key:
            raise OperationError('Chave privada nao corresponde ao certificado.')
    except OperationError as error:
        raise OperationError('TLS existente invalido antes da limpeza. Indique certificado deste servidor, chave correspondente e cadeia CA completa: '+str(error)) from error
    request['_existing_tls'] = [path.read_bytes() for path in paths]
    steps.append('TLS existente validado antes da limpeza: nome, validade, cadeia e chave; nenhuma CA criada.')


def install_existing_tls(request, root):
    material = request.get('_existing_tls')
    if not material:
        return []
    directory = root/'etc/samba/tls'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, data, mode in zip(['dc.crt','dc.key','ca.crt'], material, [0o644,0o600,0o644]):
        atomic_write(directory/name,data,mode)
    return [('tls enabled','yes'), ('tls certfile',str(directory/'dc.crt')),
            ('tls keyfile',str(directory/'dc.key')), ('tls cafile',str(directory/'ca.crt'))]



# provision_workflow.py — integrated implementation
"""Web provisioning transaction. Secrets only arrive via stdin; never enter manifests."""


import hashlib


import ipaddress


import json


import os


from pathlib import Path


import re


import shutil


import stat


import tarfile


import time


import uuid


SERVICES = ['samba', 'samba-ad-dc', 'samba-dc', 'smb', 'smbd', 'nmb', 'nmbd', 'winbind', 'named', 'bind9', 'systemd-resolved', 'chrony', 'chronyd']


PATHS = ['etc/samba', 'etc/krb5.conf', 'etc/resolv.conf', 'etc/named.conf', 'etc/bind',
         'etc/chrony.conf', 'etc/chrony', 'etc/hostname', 'etc/hosts', 'etc/step-ca', 'etc/astral-ad-dns/tls-renew.json',
         'etc/systemd/system/step-ca.service', 'etc/systemd/system/astral-ad-tls-renew.service',
         'etc/systemd/system/astral-ad-tls-renew.timer', 'usr/local/lib/astral-ad-dns/tls-renew.py',
         'etc/astral-ad-dns/provision-firewall.json', 'etc/systemd/system/astral-ad-firewall.service',
         'usr/local/lib/astral-ad-dns/firewall-restore.py', 'var/lib/samba', 'var/cache/samba']


PROGRESS_PATH = None


PROGRESS_STEPS = []


FSMO = ['SchemaMasterRole', 'DomainNamingMasterRole', 'InfrastructureMasterRole', 'RidAllocationMasterRole',
        'PdcEmulationMasterRole', 'DomainDnsZonesMasterRole', 'ForestDnsZonesMasterRole']


def optional(run, args):
    try:
        return run(args)
    except OperationError:
        return ''


def validate(request):
    for field in ['overwrite_existing','rejoin','clean_existing','setup_bind_hybrid','setup_step_ca','initialize_ca','global_catalog','dry_run','reapply_configuration']:
        if field in request and not isinstance(request[field],bool):
            raise OperationError('O campo '+field+' deve ser booleano; nenhuma limpeza foi autorizada.')
    if not isinstance(request.get('admin_password'),str):
        raise OperationError('Senha administrativa deve ser texto.')
    kind = request.get('kind', 'join')
    if kind not in ['join', 'new', 'configure']:
        raise OperationError('Operacao de provisionamento invalida.')
    realm = str(request.get('realm', '')).strip().upper()
    if not re.fullmatch(r'[A-Z0-9-]+(?:\.[A-Z0-9-]+)+', realm):
        raise OperationError('Informe um dominio DNS valido para o REALM.')
    name = str(request.get('netbios_name') or str(request.get('hostname_fqdn', '')).split('.')[0]).strip().upper()
    if not re.fullmatch(r'[A-Z0-9_-]{1,15}', name):
        raise OperationError('Nome NetBIOS deve ter de 1 a 15 letras, numeros, hifen ou sublinhado.')
    role = str(request.get('domain_role', 'DC')).upper()
    if role not in ['DC', 'RODC', 'MEMBER']:
        raise OperationError('Escolha DC, RODC ou MEMBER.')
    if not request.get('admin_password') or (kind != 'new' and not request.get('admin_username')):
        raise OperationError('Informe as credenciais administrativas do dominio.')
    if kind=='new': request['admin_username']=request.get('admin_username') or 'Administrator'
    if not isinstance(request.get('admin_username'),str): raise OperationError('Usuario administrativo deve ser texto.')
    if kind == 'new':
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', request.get('workgroup', '')):
            raise OperationError('Workgroup NetBIOS invalido.')
        fqdn = str(request.get('hostname_fqdn','')).strip().lower()
        if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',fqdn) or not fqdn.endswith('.'+realm.lower()):
            raise OperationError('Informe HOSTNAME_COMPLETO pertencente ao REALM.')
        request['hostname_fqdn'] = fqdn
        request['netbios_name'] = fqdn.split('.')[0].upper()
        if len(request['netbios_name']) > 15:
            raise OperationError('Hostname curto deve ter no maximo 15 caracteres.')
        try:
            address = ipaddress.IPv4Address(str(request.get('static_ip','')).strip())
        except ValueError as error:
            raise OperationError('Informe IP_ESTATICO valido para o DC1.') from error
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise OperationError('IP_ESTATICO deve ser o IPv4 da interface do DC1.')
        request['static_ip'] = str(address)
        if not str(request.get('network_interface','')).strip():
            raise OperationError('Informe INTERFACE_REDE para o DC1.')
        if len(request['admin_password']) < 8:
            raise OperationError('Senha administrativa deve ter ao menos oito caracteres.')
    elif kind != 'configure' or request.get('target_dc_ip'):
        try:
            partner = ipaddress.IPv4Address(str(request.get('target_dc_ip', '')).strip())
        except ValueError as error:
            raise OperationError('Informe o IPv4 do DC parceiro.') from error
        if partner.is_loopback or partner.is_unspecified or partner.is_multicast or str(partner) == '255.255.255.255':
            raise OperationError('O parceiro deve ser outro servidor, nunca localhost.')
        request['target_dc_ip'] = str(partner)
    if request.get('setup_step_ca') and not request.get('cert_password'):
        raise OperationError('Informe a senha da PKI para configurar TLS/Step-CA.')
    try:
        port=int(request.get('ca_port',8443)); hours=int(request.get('ca_cert_hours',8760))
    except (ValueError,TypeError) as error:
        raise OperationError('Porta/duracao da CA invalidas.') from error
    if not 1024<=port<=65535 or not 1<=hours<=8760:
        raise OperationError('Porta da CA: 1024 a 65535; validade do certificado: 1 a 8760 horas.')
    request.update(ca_port=port,ca_cert_hours=hours)
    interface=request.get('network_interface','').strip()
    if interface and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface):
        raise OperationError('Interface de rede invalida.')
    forwarders = normalize_forwarders(request.get('upstream_forwarders') or [])
    request.update(kind=kind, realm=realm, netbios_name=request['netbios_name'] if kind=='new' else name, domain_role=role, upstream_forwarders=forwarders)


def credentials(request):
    return ['-U' + request.get('admin_username', 'Administrator'), '--password=' + request['admin_password']]


def verify_partner_gpo(request, run):
    """Read-only check before touching the existing membership or services."""
    partner = request.get('target_dc_ip')
    if request['domain_role'] == 'MEMBER' or not partner:
        return
    try:
        run(['samba-tool', 'gpo', 'aclcheck', '-H', 'ldap://' + partner] + credentials(request))
    except OperationError as error:
        raise OperationError('Validacao de GPO/SYSVOL no DC parceiro falhou antes da limpeza. '
                             'Verifique as credenciais administrativas do dominio e as ACLs no parceiro. ' + str(error)) from error


def configure_sysvol(request, root, run, steps):
    partner = request['target_dc_ip']
    sysvol = root / 'var/lib/samba/sysvol'
    sysvol.mkdir(parents=True, exist_ok=True)
    run(['smbclient', '//' + partner + '/sysvol', '--client-protection=sign',
         '-c', 'recurse ON; prompt OFF; lcd ' + str(sysvol) + '; mget *'] + credentials(request))
    run(['samba-tool', 'ntacl', 'sysvolreset'])
    run(['samba-tool', 'gpo', 'aclcheck', '-H', 'ldap://' + partner] + credentials(request))
    steps.append('SYSVOL sincronizado; ACLs locais restauradas e GPOs do parceiro verificadas com credenciais administrativas.')


def read_level(text):
    levels = {'2000': 0, '2003': 2, '2008': 3, '2008_R2': 4, '2012': 5, '2012_R2': 6, '2016': 7}
    text = text.strip().replace('(Windows)', '').strip().replace(' ', '_').upper()
    if text not in levels:
        raise OperationError('Nivel funcional nao suportado: ' + text)
    return levels[text], text


def preflight(request, root, run, old_name, steps):
    if request['kind'] == 'configure':
        return None
    if request['kind'] == 'new':
        if (root / 'var/lib/samba/private/sam.ldb').exists() and not request.get('overwrite_existing'):
            raise OperationError('Ja existe uma base AD. Para criar um dominio novo, selecione Sobrescrever a base e configuracao local do DC1. Para preservar o dominio, escolha Reaplicar configuracao.')
        observed=run(['testparm','-s','--parameter-name=ad dc functional level','--option=ad dc functional level = 2016','/dev/null'])
        if read_level(observed)[1]!='2016': raise OperationError('O Samba instalado nao aceita nivel 2016; nenhuma base foi limpa.')
        return None
    partner = request['target_dc_ip']
    local_ips = local_ipv4s(run)
    if partner in local_ips:
        raise OperationError('O parceiro informado pertence a esta maquina.')
    answer = run(['dig', '@' + partner, '-p', '53', '_ldap._tcp.dc._msdcs.' + request['realm'].lower(), 'SRV', '+noall', '+answer', '+tries=1', '+time=3'])
    if not any('SRV' in line.split() for line in answer.splitlines() if not line.startswith(';')):
        raise OperationError('O parceiro nao respondeu com SRV LDAP do dominio; nada sera limpo.')
    info = run(['samba-tool', 'domain', 'info', partner])
    partner_name = next((line.partition(':')[2].strip().upper() for line in info.splitlines() if line.partition(':')[0].strip().lower() == 'dc netbios name'), '')
    if not partner_name or partner_name in {old_name, request['netbios_name']}:
        raise OperationError('Parceiro nao identificado ou possui o mesmo nome do alvo.')
    if request['kind'] == 'configure':
        return None
    owners = run(['samba-tool', 'fsmo', 'show', '-H', 'ldap://' + partner] + credentials(request))
    found = {}
    for label in FSMO:
        match = re.search(re.escape(label) + r' owner:\s*CN=NTDS Settings,CN=([^,]+),', owners, re.I)
        if not match:
            raise OperationError('Nao foi possivel verificar todas as funcoes FSMO; limpeza bloqueada.')
        found[label] = match[1].upper()
    if {old_name, request['netbios_name']} & set(found.values()):
        raise OperationError('Este DC detem funcoes FSMO. Transfira-as pela tela Computadores & DCs antes do reingresso.')
    partner_account = run(['samba-tool', 'computer', 'show', partner_name, '-H', 'ldap://' + partner] + credentials(request))
    uac = re.search(r'(?im)^userAccountControl:\s*(\d+)', partner_account)
    if not uac or int(uac[1]) & 0x4000000 or not int(uac[1]) & 0x2000:
        raise OperationError('O parceiro deve ser um DC gravavel.')
    levels = run(['samba-tool', 'domain', 'level', 'show', '-H', 'ldap://' + partner] + credentials(request))
    remote = {}
    for key in ['Domain function level', 'Forest function level']:
        line = next((line.partition(':')[2] for line in levels.splitlines() if line.partition(':')[0].strip() == key), None)
        if line is None:
            raise OperationError('Nao foi possivel determinar o nivel funcional do dominio/floresta.')
        remote[key] = read_level(line)
    if remote['Forest function level'][0] > remote['Domain function level'][0]:
        raise OperationError('Niveis funcionais inconsistentes.')
    default = read_level(run(['testparm', '-s', '--parameter-name=ad dc functional level', '/dev/null']))
    selected = max(default, remote['Domain function level'])
    observed = run(['testparm', '-s', '--parameter-name=ad dc functional level', '--option=ad dc functional level = ' + selected[1], '/dev/null'])
    if read_level(observed) != selected:
        raise OperationError('Samba local nao aceitou o nivel funcional exigido.')
    steps.append('DNS do parceiro validado; todas as funcoes FSMO preservadas; nivel do DC: ' + selected[1])
    return selected[1]


def ignore_runtime_entries(directory, names):
    """Samba recreates Unix sockets/FIFOs; copying their bytes is invalid."""
    return [name for name in names
            if stat.S_ISSOCK((Path(directory) / name).lstat().st_mode)
            or stat.S_ISFIFO((Path(directory) / name).lstat().st_mode)]


def snapshot(root, backup, include_database):
    mirror = backup / 'files'
    mirror.mkdir(parents=True, exist_ok=True, mode=0o700)
    for relative in PATHS:
        if include_database != relative.startswith('var/'):
            continue
        source, target = root / relative, mirror / relative
        if not source.exists() and not source.is_symlink():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_dir():
            def ignore(directory, names):
                excluded = ignore_runtime_entries(directory, names)
                if relative == 'etc/step-ca' and 'db' in names:
                    excluded.append('db')
                return excluded
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True, ignore=ignore)
        else:
            shutil.copy2(source, target)
    return mirror


def remove(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def restore_configuration(root, backup):
    captured = set(json.loads((backup / 'manifest.json').read_text()).get('captured_paths', []))
    for relative in PATHS:
        # A failed database snapshot can contain only part of a live database.
        # Never replace the live tree with an incomplete, uncommitted snapshot.
        if relative not in captured:
            continue
        # This phase never modified the CA; do not replace a live Badger database
        # with the configuration-only CA snapshot.
        if relative == 'etc/step-ca': continue
        source, target = backup / 'files' / relative, root / relative
        if not source.exists() and not source.is_symlink():
            # Only remove paths captured as absent, not unsnapshotted databases.
            remove(target)
            continue
        remove(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_dir():
            shutil.copytree(source, target, symlinks=True)
        else:
            shutil.copy2(source, target)


def service_state(run):
    return {name: {'active': optional(run, ['systemctl', 'is-active', name]).strip() == 'active',
                   'enabled': optional(run, ['systemctl', 'is-enabled', name]).strip()} for name in SERVICES}


def restore_services(states, run):
    for name, state in states.items():
        if state['enabled'] == 'masked':
            run(['systemctl', 'mask', name])
        elif state['enabled'] in ['enabled', 'disabled']:
            run(['systemctl', 'unmask', name])
            run(['systemctl', 'enable' if state['enabled'] == 'enabled' else 'disable', name])
        if state['active']:
            run(['systemctl', 'start', name])


def unit(run, choices):
    loaded,masked=[],[]
    for name in choices:
        state=optional(run,['systemctl','show',name,'-p','LoadState','--value']).strip()
        if state=='loaded': loaded.append(name)
        if state=='masked': masked.append(name)
    for name in loaded:
        if optional(run,['systemctl','is-active',name]).strip()=='active': return name
    if loaded: return loaded[0]
    if masked: return masked[0]
    raise OperationError('Unit systemd nao encontrada: '+', '.join(choices))


def tune_config(text, forwarder, level=None):
    for key, value in [('dns forwarder', forwarder), ('ad dc functional level', level)]:
        if value is None:
            continue
        text = re.sub(r'(?im)^\s*' + re.escape(key) + r'\s*=.*$', '', text)
        text, count = re.subn(r'(?im)^\s*\[global\]\s*$', '[global]\n    ' + key + ' = ' + value, text, count=1)
        if not count:
            raise OperationError('smb.conf gerado sem secao global.')
    return text


def save_manifest(backup, manifest):
    atomic_write(backup / 'manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    if PROGRESS_PATH:
        previous=json.loads(PROGRESS_PATH.read_text()) if PROGRESS_PATH.exists() else {}
        previous.update(state='running',phase=manifest.get('phase'),backup_id=manifest.get('id'),steps_completed=PROGRESS_STEPS)
        atomic_write(PROGRESS_PATH,json.dumps(previous,ensure_ascii=False))


def execute(request, root=Path('/'), run=checked_run, bind=configure_bind):
    global PROGRESS_PATH, PROGRESS_STEPS
    request = dict(request)
    progress = request.pop('_job_status_path', None)
    PROGRESS_PATH = Path(progress) if progress and Path(progress).parent == Path(os.environ.get('ASTRAL_PROVISION_JOBS_DIR','/var/lib/astral-ad-dns/provision-jobs')) and re.fullmatch(r'[a-f0-9]{32}\.json',Path(progress).name) else None
    steps, backup, manifest = [], None, {}
    PROGRESS_STEPS = steps
    remote_mutated = stopped = False
    states = {}
    try:
        validate(request)
        if request.get('dry_run'):
            return {'success': True, 'steps_completed': ['Plano: instalar dependencias ausentes, validar DNS/FSMO, backup automatico, despromocao se necessaria, limpeza e ingresso como ' + request['domain_role'], 'Forwarders: ' + ', '.join(request['upstream_forwarders']), 'Nenhum arquivo, pacote, servico ou objeto AD foi alterado.'], 'plan_only': True}
        identifier = uuid.uuid4().hex
        backup = root / 'var/backups/astral-ad-dns/provision' / identifier
        backup.mkdir(parents=True, mode=0o700)
        os.chmod(backup, 0o700)
        states = service_state(run)
        manifest = {'id': identifier, 'phase': 'preflight', 'kind': request['kind'], 'realm': request['realm'],
                    'target_name': request['netbios_name'], 'target_role': request['domain_role'], 'services': states,
                    'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'previous_hostname': optional(run,['hostname','-s']).strip(),
                    'resolver_immutable': 'i' in optional(run,['lsattr','-d',str(root/'etc/resolv.conf')]).split(' ')[0],
                    'captured_paths': []}
        save_manifest(backup, manifest)
        snapshot(root, backup, False)
        manifest['captured_paths'] = [path for path in PATHS if not path.startswith('var/')]
        save_manifest(backup, manifest)
        steps.append('Backup automatico da configuracao anterior: ' + str(backup))
        manifest['phase']='installing_dependencies'
        save_manifest(backup,manifest)
        install_dependencies(root, run, request.get('setup_bind_hybrid', False), steps)
        config = root / 'etc/samba/smb.conf'
        local_db = (root / 'var/lib/samba/private/sam.ldb').exists()
        old_name = optional(run, ['testparm', '-s', '--parameter-name=netbios name', str(config)]).strip().upper() if config.exists() else ''
        old_realm = optional(run, ['testparm', '-s', '--parameter-name=realm', str(config)]).strip().upper() if local_db else ''
        if request.get('initialize_ca') and request['kind']!='new':
            raise OperationError('Inicializar CA so e permitido em novo dominio. No reingresso, selecione a CA existente.')
        if local_db and (not old_name or not old_realm) and not (request['kind']=='new' and request.get('overwrite_existing')):
            raise OperationError('Base AD local nao pode ser identificada com seguranca; use recuperacao de backup na interface. Limpeza bloqueada para proteger o primario.')
        if request['kind'] == 'configure':
            if old_name and request['netbios_name']!=old_name:
                raise OperationError('Para alterar o nome NetBIOS escolha Reingresso; reaplicacao preserva a identidade atual.')
            account = optional(run,['samba-tool','computer','show',old_name]) if local_db else ''
            request['domain_role'] = ('RODC' if re.search(r'(?im)^primaryGroupID:\s*521',account) else 'DC') if local_db else 'MEMBER'
        if old_realm and old_realm != request['realm'] and request['kind']!='new':
            raise OperationError('A base local pertence a outro dominio; migracao entre dominios exige um fluxo dedicado.')
        if request['kind']=='new':
            if request['static_ip'] not in local_ipv4s(run): raise OperationError('IP_ESTATICO nao esta atribuido a esta maquina; verifique o IP informado.')
            run(['ip','link','show','dev',request['network_interface']])
        prepare_existing_tls(request, root, run, steps)
        level = preflight(request, root, run, old_name, steps)
        verify_partner_gpo(request, run)
        if request.get('setup_step_ca') and request.get('initialize_ca') and not (root/'etc/step-ca/config/ca.json').exists():
            preferred=request['ca_port']
            request['ca_port']=allocate_ca_port(root,run,preferred)
            steps.append('Porta da nova CA selecionada automaticamente: '+str(request['ca_port'])+' (preferida: '+str(preferred)+'); listeners existentes preservados.')
        if request['kind'] == 'configure' and not config.exists():
            raise OperationError('Nao existe configuracao Samba para reaplicar; escolha novo dominio ou ingresso.')
        joined_member=(root/'var/lib/samba/private/secrets.tdb').exists()
        if request['kind']=='configure':
            if not (local_db or joined_member): raise OperationError('Esta maquina ainda nao possui ingresso valido. Escolha Novo dominio ou Ingresso em vez de reaplicar configuracao.')
            manifest['joined']=True
        if request['kind']=='join' and request['netbios_name']!=old_name:
            collision=optional(run,['samba-tool','computer','show',request['netbios_name'],'-H','ldap://'+request['target_dc_ip']]+credentials(request))
            if collision: raise OperationError('O novo nome ja pertence a outra conta no AD. Escolha outro nome antes de despromover o servidor atual.')
        if request['kind'] == 'join' and (local_db or joined_member) and not request.get('rejoin'):
            raise OperationError('Existe configuracao local. Selecione Reingresso com backup automatico ou Reaplicar configuracao.')
        if request['kind']=='join' and not (local_db or joined_member) and not request.get('rejoin'):
            account=optional(run,['samba-tool','computer','show',request['netbios_name'],'-H','ldap://'+request['target_dc_ip']]+credentials(request))
            if account: raise OperationError('Ja existe uma conta com este nome no AD. Selecione Reingresso para autorizar sua substituicao apos backup.')
        previous_tls = re.findall(r'(?im)^\s*(tls (?:enabled|keyfile|certfile|cafile|verify peer))\s*=\s*(.+)$',config.read_text()) if config.exists() else []
        manifest.update(old_name=old_name, old_realm=old_realm, target_role=request['domain_role'], partner=request.get('target_dc_ip',''), forwarders=request['upstream_forwarders'], setup_bind_hybrid=request.get('setup_bind_hybrid',False),global_catalog=request.get('global_catalog',True))
        save_manifest(backup, manifest)
        if request['kind'] != 'configure':
            stop_names={'samba','samba-ad-dc','samba-dc','smb','smbd','nmb','nmbd','winbind'}
            if request['domain_role']!='MEMBER': stop_names.update(['named','bind9','systemd-resolved'])
            for name, state in states.items():
                if state['active'] and name in stop_names:
                    run(['systemctl', 'stop', name])
            stopped = True
            snapshot(root, backup, True)
            manifest['captured_paths'] = PATHS
        archive = backup / 'previous-state.tar.gz'
        with tarfile.open(archive, 'w:gz', dereference=False) as tar:
            tar.add(backup / 'files', arcname='files')
        archive.chmod(0o600)
        digest = hashlib.sha256()
        with archive.open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024), b''):
                digest.update(block)
        manifest['archive_sha256'] = digest.hexdigest()
        with tarfile.open(archive) as tar:
            if not tar.getmembers():
                raise OperationError('Backup automatico vazio; limpeza bloqueada.')
        manifest['phase'] = 'backup_verified'
        save_manifest(backup, manifest)
        steps.append('Backup verificado (SHA256); base/configuracao anteriores preservadas antes de qualquer limpeza.')
        if request['kind'] in ['join','new']:
            resolver=root/'etc/resolv.conf'
            optional(run,['chattr','-i',str(resolver)])
            remove(resolver)
            servers=[request['target_dc_ip']] if request['kind']=='join' else request['upstream_forwarders']
            atomic_write(resolver,'search '+request['realm'].lower()+'\n'+''.join('nameserver '+server+'\n' for server in servers),0o644)
        if request.get('setup_step_ca') and request.get('initialize_ca') and (root/'etc/step-ca/config/ca.json').exists():
            address=json.loads((root/'etc/step-ca/config/ca.json').read_text()).get('address','')
            if ':' in address: request['ca_port']=int(address.rsplit(':',1)[1])
        configure_firewall(request, root, backup, run, steps)
        primary_tls = []
        if request['kind']=='new':
            if request.get('overwrite_existing'):
                manifest['phase']='replacing_local_domain'
                save_manifest(backup,manifest)
                for relative in ['var/lib/samba','var/cache/samba','etc/samba/smb.conf']:
                    remove(root/relative)
                (root/'var/lib/samba').mkdir(parents=True,exist_ok=True)
                (root/'etc/samba').mkdir(parents=True,exist_ok=True)
                previous_tls=[]
                steps.append('Substituicao do DC1 autorizada: base e configuracao Samba anteriores removidas apos backup; novo dominio sera criado, sem recuperar a base anterior.')
            configure_identity(request,root,run,steps)
            if request.get('setup_step_ca'):
                manifest['phase']='primary_pki'
                save_manifest(backup,manifest)
                remote_mutated=True  # Preserve any newly created CA on later failure.
                primary_tls=configure_pki(request,root,run,unit(run,['samba','samba-ad-dc','samba-dc']),steps)
            configure_ntp(request,root,run,steps)
        elif request['kind']=='configure':
            candidates=local_ipv4s(run)
            request['host_ip']=request.get('static_ip') or next((value for value in candidates if value.count('.')==3),'')
            request['hostname_fqdn']=(old_name or request['netbios_name']).lower()+'.'+request['realm'].lower()
        if request['kind'] == 'join':
            partner = request['target_dc_ip']
            # Detect an account left by a failed join as well as a currently provisioned DC.
            account = optional(run, ['samba-tool', 'computer', 'show', old_name or request['netbios_name'], '-H', 'ldap://' + partner] + credentials(request))
            is_dc = bool(re.search(r'(?im)^primaryGroupID:\s*(516|521)\s*$', account))
            if is_dc or local_db:
                manifest['phase'] = 'demotion_attempted'
                save_manifest(backup, manifest)
                remote_mutated = True  # A failed demotion can still have replicated partial changes.
                dc_stopped = True
                try:
                    if not local_db:
                        raise OperationError('Existe uma conta DC no parceiro, mas nao existe sam.ldb local para despromocao normal.')
                    # The offline snapshot is complete. Native demotion asks the
                    # partner to pull final changes from this DC via DRS RPC.
                    # Samba must run for that synchronization, even though it
                    # must be stopped again before any cleanup or dead-DC removal.
                    dc_service = unit(run, ['samba', 'samba-ad-dc', 'samba-dc'])
                    try:
                        dc_stopped = False
                        run(['systemctl', 'start', dc_service])
                        if run(['systemctl', 'is-active', dc_service]).strip() != 'active':
                            raise OperationError('Samba local nao ficou ativo para a despromocao: ' + dc_service)
                        steps.append('Backup offline concluido; Samba local ativo para sincronizacao final da despromocao.')
                        run(['samba-tool', 'domain', 'demote', '--server=' + partner, '-s', str(config)] + credentials(request))
                    finally:
                        run(['systemctl', 'stop', dc_service])
                        dc_stopped = True
                except OperationError as demotion_error:
                    if not dc_stopped:
                        raise OperationError('Nao foi possivel parar o Samba apos tentativa de despromocao; limpeza bloqueada. ' + str(demotion_error)) from demotion_error
                    if not request.get('clean_existing'):
                        raise OperationError('Despromocao nao concluiu. Causa: ' + str(demotion_error) +
                                             '. Backup preservado; se a base/conta anterior estiver inutilizavel, autorize a limpeza de registros orfaos na interface e retome o reingresso.') from demotion_error
                    steps.append('Despromocao normal indisponivel; limpeza do DC anterior explicitamente autorizada, com Samba local parado.')
                    run(['samba-tool', 'domain', 'demote', '--remove-other-dead-server=' + (old_name or request['netbios_name']), '-H', 'ldap://' + partner] + credentials(request))
                steps.append('DC secundario anterior despromovido; funcoes FSMO do parceiro preservadas.')
            elif account:
                remote_mutated = True
                run(['samba-tool', 'computer', 'delete', old_name or request['netbios_name'], '-H', 'ldap://' + partner] + credentials(request))
            for relative in ['var/lib/samba', 'var/cache/samba', 'etc/samba/smb.conf']:
                remove(root / relative)
            (root / 'etc/samba').mkdir(parents=True, exist_ok=True)
            (root / 'var/lib/samba').mkdir(parents=True, exist_ok=True)
            steps.append('Estado Samba anterior limpo somente apos backup e despromocao/remocao da conta local.')
            configure_identity(request,root,run,steps)
            resolver = root / 'etc/resolv.conf'
            optional(run, ['chattr', '-i', str(resolver)])
            remove(resolver)
            atomic_write(resolver, 'search ' + request['realm'].lower() + '\nnameserver ' + partner + '\n', 0o644)
            configure_ntp(request,root,run,steps)
            args = ['samba-tool', 'domain', 'join', request['realm'], request['domain_role'], '--server=' + partner,
                    '--realm=' + request['realm'], '--option=netbios name = ' + request['netbios_name']]
            if request['domain_role'] != 'MEMBER':
                args += ['--dns-backend=SAMBA_INTERNAL', '--option=ad dc functional level = ' + level]
            manifest['phase'] = 'join_attempted'
            save_manifest(backup, manifest)
            remote_mutated = True
            run(args + credentials(request))
            manifest['joined'] = True
            save_manifest(backup,manifest)
            if request['domain_role'] != 'MEMBER':
                manifest['phase'] = 'sysvol_configuration'
                save_manifest(backup, manifest)
                configure_sysvol(request, root, run, steps)
        elif request['kind'] == 'new':
            remove(config)
            manifest['phase'] = 'provision_attempted'
            save_manifest(backup, manifest)
            run(['samba-tool', 'domain', 'provision', '--use-rfc2307', '--realm=' + request['realm'],
                 '--domain=' + request['workgroup'].upper(), '--server-role=dc', '--dns-backend=SAMBA_INTERNAL',
                 '--option=netbios name = ' + request['netbios_name'], '--adminpass=' + request['admin_password']])
            level = '2016'
            manifest['joined'] = True
            remote_mutated = True
            save_manifest(backup,manifest)
        if request['kind'] == 'configure' and request['domain_role'] != 'MEMBER' and request.get('target_dc_ip'):
            remote_mutated = True  # SYSVOL ACL reset must not restore a raw old database.
            manifest['phase'] = 'sysvol_configuration'
            save_manifest(backup, manifest)
            configure_sysvol(request, root, run, steps)
        if not config.exists():
            raise OperationError('Samba nao produziu smb.conf; backup preservado.')
        if request['kind']=='new':
            directory=DIRECTORY_SCRIPT
            observed=json.loads(run(['/usr/bin/python3','-c',directory,'--inspect']))
            if observed.get('schema_version',0)<88:
                run(['samba-tool','domain','schemaupgrade','--schema=2019'])
                run(['samba-tool','domain','functionalprep','--function-level=2016'])
            levels = run(['samba-tool','domain','level','show','-s',str(config)])
            if any(not re.search(re.escape(label)+r':\s*(?:\(Windows\)\s*)?2016\s*$', levels, re.M) for label in ['Domain function level','Forest function level']):
                run(['samba-tool','domain','functionalprep','--function-level=2016'])
                run(['samba-tool','domain','level','raise','--domain-level=2016','--forest-level=2016','--option=ad dc functional level = 2016'])
            steps.append('Novo dominio: schema 2019 ou superior verificado; nivel funcional 2016 selecionado no provisionamento.')
        if request['kind']=='join' and not request.get('setup_step_ca') and not request.get('_existing_tls'):
            previous_tls_dir=backup/'files/var/lib/samba/private/tls'
            if previous_tls_dir.is_dir():
                shutil.copytree(previous_tls_dir,root/'var/lib/samba/private/tls',dirs_exist_ok=True)
                cert=root/'var/lib/samba/private/tls/cert.pem'
                if cert.exists():
                    try: run(['openssl','x509','-in',str(cert),'-noout','-checkhost',request['hostname_fqdn']])
                    except OperationError:
                        raise OperationError('Ingresso concluido, mas o certificado anterior nao corresponde ao novo FQDN. Selecione TLS/Step-CA em Reaplicar configuracao pela interface.')
        manifest['phase'] = 'configuration'
        save_manifest(backup, manifest)
        forwarder = request['upstream_forwarders'][0] if request['kind'] == 'new' else request.get('target_dc_ip') or request['upstream_forwarders'][0]
        bind_error = None
        if request.get('setup_bind_hybrid') and request['domain_role'] != 'MEMBER':
            try:
                steps.extend(bind({'forwarders': request['upstream_forwarders']}, root, run))
                forwarder = '127.0.0.1:5353'
            except Exception as error:
                bind_error = str(error)
        text = tune_config(config.read_text(), forwarder, level)
        for key,value in (primary_tls or install_existing_tls(request, root) or previous_tls):
            text = re.sub(r'(?im)^\s*' + re.escape(key) + r'\s*=.*$', '', text)
            text = text.replace('[global]','[global]\n    ' + key + ' = ' + value,1)
        if request.get('network_interface'):
            interface=request['network_interface']
            run(['ip','link','show','dev',interface])
            for key,value in [('interfaces','lo '+interface),('bind interfaces only','yes')]:
                text=re.sub(r'(?im)^\s*'+re.escape(key)+r'\s*=.*$','',text)
                text=text.replace('[global]','[global]\n    '+key+' = '+value,1)
        atomic_write(config,text,0o644)
        kerberos = root / 'var/lib/samba/private/krb5.conf'
        if kerberos.exists():
            atomic_write(root / 'etc/krb5.conf', kerberos.read_bytes(), 0o644)
        else:
            atomic_write(root/'etc/krb5.conf','[libdefaults]\n default_realm = '+request['realm']+'\n dns_lookup_realm = false\n dns_lookup_kdc = true\n rdns = false\n[domain_realm]\n .'+request['realm'].lower()+' = '+request['realm']+'\n '+request['realm'].lower()+' = '+request['realm']+'\n',0o644)
        if root == Path('/') and shutil.which('restorecon'):
            run(['restorecon', '-R', str(root / 'var/lib/samba'), str(config)])
        if request['kind']=='configure':
            configure_ntp(request,root,run,steps)
        if request['domain_role'] == 'MEMBER':
            services = [unit(run, ['smb', 'smbd']), unit(run, ['winbind'])]
        else:
            services = [unit(run, ['samba', 'samba-ad-dc', 'samba-dc'])]
        if request.get('setup_step_ca') and request['domain_role']!='MEMBER' and request['kind']!='new':
            remote_mutated=True  # PKI initialization/issuance must never trigger raw old-domain restoration.
            tls_pairs=configure_pki(request,root,run,services[0],steps)
            text=config.read_text()
            for key,value in tls_pairs:
                text=re.sub(r'(?im)^\s*'+re.escape(key)+r'\s*=.*$','',text)
                text=text.replace('[global]','[global]\n    '+key+' = '+value,1)
            atomic_write(config,text,0o644)
        for name in services:
            run(['systemctl', 'unmask', name])
            run(['systemctl', 'enable', name])
            run(['systemctl', 'restart', name])
            if run(['systemctl', 'is-active', name]).strip() != 'active':
                raise OperationError('Servico nao ficou ativo: ' + name)
        if request['domain_role'] != 'MEMBER' and request['kind'] == 'configure':
            remote_mutated = True
        if request['domain_role'] == 'MEMBER':
            run(['net', 'ads', 'testjoin', '-s', str(config)])
            run(['chattr','+i',str(root/'etc/resolv.conf')])
        else:
            for attempt in range(15):
                try:
                    run(['samba-tool', 'domain', 'level', 'show', '-s', str(config)])
                    break
                except OperationError:
                    if attempt==14: raise
                    time.sleep(1)
            directory = DIRECTORY_SCRIPT
            directory_args=['/usr/bin/python3','-c',directory]
            if request['domain_role']=='RODC':
                if not request.get('target_dc_ip'): raise OperationError('Informe o DC gravavel parceiro na tela para configurar o catalogo global do RODC.')
                directory_args+=['--server='+request['target_dc_ip'],'--username='+request['admin_username'],'--password='+request['admin_password']]
            configured=json.loads(run(directory_args+([] if request.get('global_catalog',True) else ['--disable-gc'])))
            steps.append('Catalogo global configurado; particoes DNS verificadas: '+json.dumps(configured))
            run(['systemctl','restart',services[0]])
            if request.get('global_catalog',True):
                for attempt in range(15):
                    try:
                        run(['/usr/bin/python3','-c',directory,'--verify'])
                        break
                    except OperationError:
                        if attempt == 14: raise
                        time.sleep(1)
                run(['dig','@127.0.0.1','_gc._tcp.' + request['realm'].lower(),'SRV','+short','+tries=1','+time=3'])
                steps.append('Catalogo global confirmado por isGlobalCatalogReady; portas 3268/3269 garantidas no firewall.')
            configure_dns_records(request,run,steps)
            resolver=root/'etc/resolv.conf'
            optional(run,['chattr','-i',str(resolver)])
            remove(resolver)
            content='search '+request['realm'].lower()+'\nnameserver 127.0.0.1\n'
            if request.get('target_dc_ip'): content+='nameserver '+request['target_dc_ip']+'\n'
            atomic_write(resolver,content,0o644)
            run(['chattr','+i',str(resolver)])
            if request['kind'] == 'join':
                health = json.loads(run(['samba-tool', 'drs', 'showrepl', '--json'] + credentials(request)))
                inbound = [entry for entry in health.get('repsFrom', []) if not entry.get('is deleted', False)]
                if not inbound or any(entry.get('consecutive failures', 1) != 0 or entry.get('last success') in [None,0,'0','NTTIME(0)'] for entry in inbound):
                    raise OperationError('Ingresso efetuado, mas replicacao nao foi confirmada. Configuracao e backup disponiveis para reaplicacao pela interface.')
        manifest.update(phase='configuration_pending' if bind_error else 'complete', joined=True,ca_port=request.get('ca_port') if request.get('setup_step_ca') else None,ca_url=request.get('ca_url'))
        save_manifest(backup, manifest)
        steps.append('Papel ' + request['domain_role'] + ' ativado e verificacoes Samba concluidas.')
        if bind_error:
            steps.append('[AVISO] BIND solicitado nao foi concluido. Use Reaplicar configuracao pela interface; o ingresso foi preservado. ' + bind_error)
        return {'success': not bool(bind_error), 'joined': True, 'configuration_pending': bool(bind_error),
                'message': 'Configuracao BIND pendente; ingresso preservado.' if bind_error else 'Provisionamento concluido.',
                'steps_completed': steps, 'ca_port':manifest.get('ca_port'),'ca_url':manifest.get('ca_url'), 'backup_id': identifier, 'backup_path': str(backup), 'plan_only': False}
    except Exception as error:
        message = str(error)
        recovery_required = remote_mutated and not manifest.get('joined',False)
        if backup:
            manifest['failure_phase'] = manifest.get('phase')
            manifest['phase'] = 'configuration_pending' if manifest.get('joined') else ('recovery_required' if remote_mutated else 'failed_before_remote_change')
            try:
                if not remote_mutated:
                    optional(run, ['chattr', '-i', str(root / 'etc/resolv.conf')])
                    restore_configuration(root, backup)
                    if manifest.get('resolver_immutable'): run(['chattr','+i',str(root/'etc/resolv.conf')])
                    if manifest.get('previous_hostname'): run(['hostnamectl','set-hostname',manifest['previous_hostname']])
                    if stopped:
                        restore_services(states, run)
                    steps.append('Configuracao anterior restaurada; nenhuma alteracao remota AD foi confirmada.')
                elif manifest.get('joined'):
                    steps.append('[AVISO] Ingresso preservado; use Reaplicar configuracao para concluir a etapa pendente. Nao e necessario refazer o ingresso.')
                else:
                    steps.append('[AVISO] Alteracoes remotas podem ter ocorrido. Base antiga nao sera reativada automaticamente; retome o reingresso pela interface com o backup preservado.')
            except Exception as rollback:
                message += '; restauracao pendente: ' + str(rollback)
            save_manifest(backup, manifest)
        # Redact credentials even if a third-party command includes them in its error.
        for secret in [request.get('admin_password'),request.get('cert_password')]:
            if secret:
                message = message.replace(secret, '[REDACTED]')
        return {'success': False, 'message': message, 'error': message, 'steps_completed': steps,
                'backup_id': manifest.get('id'), 'backup_path': str(backup) if backup else None,
                'recovery_required': recovery_required, 'joined': bool(manifest.get('joined')), 'configuration_pending': bool(manifest.get('joined')), 'plan_only': bool(request.get('dry_run'))}


DIRECTORY_SCRIPT = '#!/usr/bin/python3\n"""Run with the Samba distro Python; local system session only, no passwords."""\nimport argparse\nimport json\nimport socket\nimport ldb\nfrom samba.auth import system_session\nfrom samba.param import LoadParm\nfrom samba.samdb import SamDB\n\n\ndef configure(gc=True, repair=True, inspect=False, server=None, username=None, password=None):\n    lp = LoadParm()\n    lp.load_default()\n    db = SamDB(session_info=system_session(), lp=lp)\n    schema = db.search(base=db.get_schema_basedn(), scope=ldb.SCOPE_BASE, attrs=[\'objectVersion\'])[0]\n    if inspect:\n        return {\'schema_version\': int(schema[\'objectVersion\'][0])}\n    root = db.search(base=\'\', scope=ldb.SCOPE_BASE, attrs=[\'dsServiceName\',\'isGlobalCatalogReady\'])[0]\n    ntds = ldb.Dn(db, root[\'dsServiceName\'][0].decode())\n    if server:\n        from samba.credentials import Credentials\n        credentials=Credentials();credentials.guess(lp)\n        credentials.set_username(username);credentials.set_password(password)\n        # The DN was obtained from the local DC, so this changes that DC\'s GC flag,\n        # never the partner\'s NTDS settings. A RODC sends the write to a writable DC.\n        db=SamDB(url=\'ldap://\'+server,credentials=credentials,lp=lp)\n        ntds=ldb.Dn(db,str(ntds))\n    current = db.search(base=ntds, scope=ldb.SCOPE_BASE, attrs=[\'options\'])[0]\n    options = int(current.get(\'options\',[b\'0\'])[0])\n    updated = options | 1 if gc else options & ~1\n    if updated != options:\n        message = ldb.Message()\n        message.dn = ntds\n        message[\'options\'] = ldb.MessageElement(str(updated), ldb.FLAG_MOD_REPLACE, \'options\')\n        db.modify(message)\n    repaired = []\n    if repair:\n        realm = lp.get(\'realm\').lower()\n        partitions = db.search(base=\'CN=Partitions,\' + str(db.get_config_basedn()), scope=ldb.SCOPE_ONELEVEL,\n            expression=\'(|(dnsRoot=DomainDnsZones.\' + realm + \')(dnsRoot=ForestDnsZones.\' + realm + \'))\', attrs=[\'msDS-SDReferenceDomain\'])\n        for partition in partitions:\n            if \'msDS-SDReferenceDomain\' not in partition:\n                message = ldb.Message()\n                message.dn = partition.dn\n                message[\'msDS-SDReferenceDomain\'] = ldb.MessageElement(str(db.get_default_basedn()), ldb.FLAG_MOD_ADD, \'msDS-SDReferenceDomain\')\n                db.modify(message)\n                repaired.append(str(partition.dn))\n    return {\'global_catalog_enabled\': bool(updated & 1), \'previous_options\': options, \'options\': updated,\n            \'dns_partitions_repaired\': repaired}\n\n\nif __name__ == \'__main__\':\n    parser = argparse.ArgumentParser()\n    parser.add_argument(\'--disable-gc\', action=\'store_true\')\n    parser.add_argument(\'--inspect\', action=\'store_true\')\n    parser.add_argument(\'--verify\', action=\'store_true\')\n    parser.add_argument(\'--server\')\n    parser.add_argument(\'--username\')\n    parser.add_argument(\'--password\')\n    args = parser.parse_args()\n    if args.verify:\n        lp=LoadParm(); lp.load_default()\n        db=SamDB(session_info=system_session(),lp=lp)\n        value=db.search(base=\'\',scope=ldb.SCOPE_BASE,attrs=[\'isGlobalCatalogReady\'])[0]\n        ready=value.get(\'isGlobalCatalogReady\',[b\'FALSE\'])[0].decode().upper() == \'TRUE\'\n        if ready:\n            for port in [3268,3269]:\n                with socket.create_connection((\'127.0.0.1\',port),timeout=3): pass\n        print(json.dumps({\'ready\':ready}))\n        raise SystemExit(0 if ready else 1)\n    print(json.dumps(configure(not args.disable_gc, inspect=args.inspect,server=args.server,username=args.username,password=args.password)))\n'

if __name__ == '__main__':
    import sys
    request = json.load(sys.stdin)
    if request.get('kind', 'new') != 'new':
        raise SystemExit('Esta pilha e exclusiva do DC1.')
    request['kind'] = 'new'
    lock_path = Path('/run/lock/astral-ad-operations.lock')
    lock_path.parent.mkdir(parents=True,exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(execute(request),ensure_ascii=False))
