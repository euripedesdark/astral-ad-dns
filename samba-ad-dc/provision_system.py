"""Distro-aware preparation, non-destructive firewall and signed NTP for web jobs."""
import json
from pathlib import Path
import re
import shutil
import socket
import itertools
from ad_operations import OperationError, atomic_write

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
    candidates = run(['hostname','-I']).split()
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
