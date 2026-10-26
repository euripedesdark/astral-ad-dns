#!/usr/bin/env python3
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
from ad_operations import OperationError, atomic_write, checked_run, local_ipv4s, configure_bind, normalize_forwarders
from provision_system import install_dependencies, configure_firewall, configure_ntp, configure_identity, configure_dns_records, allocate_ca_port
from provision_pki import configure_pki
from provision_tls import prepare_existing_tls, install_existing_tls

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
            directory=str(Path(__file__).with_name('directory_config.py'))
            observed=json.loads(run(['/usr/bin/python3',directory,'--inspect']))
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
            directory = str(Path(__file__).with_name('directory_config.py'))
            directory_args=['/usr/bin/python3',directory]
            if request['domain_role']=='RODC':
                if not request.get('target_dc_ip'): raise OperationError('Informe o DC gravavel parceiro na tela para configurar o catalogo global do RODC.')
                directory_args+=['--server='+request['target_dc_ip'],'--username='+request['admin_username'],'--password='+request['admin_password']]
            configured=json.loads(run(directory_args+([] if request.get('global_catalog',True) else ['--disable-gc'])))
            steps.append('Catalogo global configurado; particoes DNS verificadas: '+json.dumps(configured))
            run(['systemctl','restart',services[0]])
            if request.get('global_catalog',True):
                for attempt in range(15):
                    try:
                        run(['/usr/bin/python3',directory,'--verify'])
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
