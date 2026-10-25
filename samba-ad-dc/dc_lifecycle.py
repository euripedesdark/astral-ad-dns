#!/usr/bin/env python3
"""Run on the selected Samba controller; requests/credentials arrive on stdin."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


ROLES = {
    'schema': 'SchemaMasterRole', 'naming': 'DomainNamingMasterRole',
    'infrastructure': 'InfrastructureMasterRole', 'rid': 'RidAllocationMasterRole',
    'domaindns': 'DomainDnsZonesMasterRole', 'forestdns': 'ForestDnsZonesMasterRole',
    'pdc': 'PdcEmulationMasterRole',
}


class TransitionError(RuntimeError):
    pass


def run_command(args):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired as error:
        raise TransitionError('Tempo limite ao executar ' + args[0] + '; confira o estado da operação antes de repetir.') from error
    if result.returncode:
        raise TransitionError((result.stderr or result.stdout)[-3000:])
    return result.stdout


def credentials(request):
    return ['-U' + request['admin_username'], '--password=' + request['admin_password']]


def value(ldif, attribute):
    for line in ldif.splitlines():
        key, separator, text = line.partition(': ')
        if separator and key.lower() == attribute.lower():
            return text.strip()
    return ''


def rodc(ldif):
    return value(ldif, 'primaryGroupID') == '521' or int(value(ldif, 'userAccountControl') or '0') & 0x4000000 != 0


def writable(ldif):
    return not rodc(ldif) and int(value(ldif, 'userAccountControl') or '0') & 0x2000 != 0


def owners(output):
    result = {}
    for line in output.splitlines():
        match = re.match(r'\s*(\w+) owner:\s*(.*)', line, re.I)
        if match:
            for role, label in ROLES.items():
                if match[1].lower() == label.lower():
                    server = re.search(r'CN=NTDS Settings,CN=([^,]+),', match[2], re.I)
                    if server:
                        result[role] = server[1].upper()
    return result


def fsmo(request, host, run):
    return owners(run(['samba-tool', 'fsmo', 'show', '-H', 'ldap://' + host] + credentials(request)))


def healthy_replication(request, host, run):
    data = json.loads(run(['samba-tool', 'drs', 'showrepl', host, '--json'] + credentials(request)))
    inbound = [entry for entry in data.get('repsFrom', []) if not entry.get('is deleted', False)]
    if not inbound or any(entry.get('consecutive failures', 1) != 0 or entry.get('last success') in [None, 0, '0', 'NTTIME(0)', 'Thu Jan  1 00:00:00 1970 UTC'] for entry in inbound):
        raise TransitionError('Replicação de entrada ausente ou com falhas; corrija antes da transição.')


def preflight(request, run):
    for key in ['target_name', 'target_hostname', 'primary_name', 'primary_hostname', 'realm']:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', request.get(key, '')):
            raise TransitionError('Identificação de domínio/controlador inválida.')
    if not request.get('admin_username') or not request.get('admin_password'):
        raise TransitionError('Credenciais administrativas do domínio são obrigatórias.')
    name = run(['testparm', '-s', '--parameter-name=netbios name']).strip().upper()
    realm = run(['testparm', '-s', '--parameter-name=realm']).strip().upper()
    if name != request['target_name'] or realm != request['realm'].upper():
        raise TransitionError('Host selecionado não corresponde à identidade/domínio solicitados.')
    current = fsmo(request, request['primary_hostname'], run)
    if current.get('pdc') != request['primary_name'] or name == current.get('pdc'):
        raise TransitionError('O principal mudou ou o alvo já é principal; atualize a lista.')
    primary = run(['samba-tool', 'computer', 'show', request['primary_name'], '-H', 'ldap://' + request['primary_hostname']] + credentials(request))
    if not writable(primary):
        raise TransitionError('O parceiro principal deve ser um DC gravável saudável.')
    local = run(['samba-tool', 'computer', 'show', name])
    healthy_replication(request, request['target_hostname'], run)
    healthy_replication(request, request['primary_hostname'], run)
    contexts = sorted({entry['naming context'] for entry in json.loads(run(['samba-tool', 'drs', 'showrepl', request['target_hostname'], '--json'] + credentials(request))).get('repsFrom', []) if not entry.get('is deleted', False) and entry.get('naming context')})
    if not contexts:
        raise TransitionError('Não foi possível identificar os contextos reais de replicação.')
    return local, current, contexts


def replication_contexts(realm):
    domain = ','.join('DC=' + part for part in realm.lower().split('.'))
    return [domain, 'CN=Configuration,' + domain, 'CN=Schema,CN=Configuration,' + domain,
            'DC=DomainDnsZones,' + domain, 'DC=ForestDnsZones,' + domain]


def promote_primary(request, run=run_command):
    local, before, contexts = preflight(request, run)
    if not writable(local):
        raise TransitionError('Promover a principal exige DC gravável; primeiro converta o RODC.')
    if set(before) != set(ROLES):
        raise TransitionError('Não foi possível identificar as sete funções FSMO; nada foi transferido.')
    steps = ['Pré-verificação: identidade, parceiro gravável, funções FSMO e replicação saudáveis.']
    if request.get('dry_run'):
        return steps + ['[SIMULAÇÃO] Transferir sete funções FSMO ao alvo, PDC por último; manter o antigo principal como DC gravável.']
    transferred = []
    try:
        # PDC goes last so the visible primary changes only after the other roles.
        for role in ROLES:
            run(['samba-tool', 'fsmo', 'transfer', '--role=' + role,
                 '-H', 'ldap://' + request['target_hostname']] + credentials(request))
            after = fsmo(request, request['target_hostname'], run)
            if after.get(role) != request['target_name']:
                raise TransitionError('Transferência não confirmada para função ' + role)
            transferred.append(role)
        if fsmo(request, request['target_hostname'], run) != {role: request['target_name'] for role in ROLES}:
            raise TransitionError('Propriedade FSMO divergente após transferência.')
        # Keep the former primary and the console observer consistent before success.
        hosts = {request['primary_hostname'], request.get('observer_hostname', '')} - {'', request['target_hostname']}
        for host in hosts:
            for context in contexts:
                run(['samba-tool', 'drs', 'replicate', host, request['target_hostname'], context] + credentials(request))
            if fsmo(request, host, run) != {role: request['target_name'] for role in ROLES}:
                raise TransitionError('PDC ainda não confirmado no observador ' + host)
        steps += ['Funções FSMO transferidas e confirmadas: ' + ', '.join(transferred),
                  'Novo principal: ' + request['target_name'] + '. Antigo principal mantido como DC gravável secundário.']
        return steps
    except Exception as error:
        # FSMO transfers are distributed operations. Never silently seize or reverse them.
        raise TransitionError(str(error) + '; funções já confirmadas no alvo: ' + ', '.join(transferred) +
                              '. Consulte FSMO e retome a transferência; nenhum DC foi despromovido/removido.') from error


def rewrite_paths(text, stage, live):
    text = text.replace(str(stage), str(live))
    text = re.sub(r'(?im)^\s*(dns forwarder|server services)\s*=.*$', '', text)
    return re.sub(r'(?im)^\s*\[global\]\s*$', '[global]\n    dns forwarder = 127.0.0.1:5353', text, count=1)


def write_file(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.astral-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'w') as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def promote_writable(request, root=Path('/'), run=run_command):
    local, before, contexts = preflight(request, run)
    if not rodc(local):
        raise TransitionError('Selecione um RODC para converter em DC gravável secundário.')
    if request['target_name'] in before.values():
        raise TransitionError('O alvo não pode possuir funções FSMO.')
    if not request.get('rejoin_confirmed') and not request.get('dry_run'):
        raise TransitionError('Confirme a interrupção e o novo ingresso do RODC como DC gravável.')
    if request.get('dry_run'):
        return ['[SIMULAÇÃO] Backup do domínio no parceiro gravável, cópia local da réplica, despromoção nativa do RODC e novo ingresso DC com SAMBA_INTERNAL.',
                '[SIMULAÇÃO] Validar DC gravável e replicação; não transferir FSMO.']
    live = root / 'var/lib/samba'
    config = root / 'etc/samba/smb.conf'
    if not (live / 'private/sam.ldb').is_file() or not config.is_file():
        raise TransitionError('Este fluxo exige instalação Samba padrão em /var/lib/samba e /etc/samba/smb.conf.')
    # Check BIND before interrupting the RODC. The recursive resolver stays alive.
    dns = run(['dig', '@127.0.0.1', '-p', '5353', '.', 'SOA', '+tries=1', '+time=3'])
    if 'status: NOERROR' not in dns:
        raise TransitionError('BIND recursivo não está saudável em 127.0.0.1:5353.')
    active = []
    for unit in ['samba', 'samba-dc', 'samba-ad-dc']:
        try:
            if run(['systemctl', 'is-active', unit]).strip() == 'active':
                active.append(unit)
        except TransitionError:
            pass
    if len(active) != 1:
        raise TransitionError('Identifique um único serviço Samba DC ativo antes da conversão.')
    identifier = uuid.uuid4().hex
    backup = root / 'var/backups/samba' / ('rodc-before-writable-' + identifier)
    backup.mkdir(parents=True, mode=0o700)
    previous = live.with_name('samba.rodc-before-writable-' + identifier)
    stage = Path(tempfile.mkdtemp(prefix='samba.writable-', dir=live.parent))
    saved_config = backup / 'smb.conf'
    shutil.copy2(config, saved_config)
    saved_config.chmod(0o600)
    demoted = installed = attempted_demote = stopped = False
    try:
        run(['samba-tool', 'domain', 'backup', 'online', '--server=' + request['primary_hostname'], '--targetdir=' + str(backup)] + credentials(request))
        if not list(backup.glob('*.tar.bz2')):
            raise TransitionError('Backup nativo não foi produzido; RODC permanece ativo.')
        old_sysvol = Path(run(['testparm', '-s', '--section-name=sysvol', '--parameter-name=path', str(config)]).strip())
        if not old_sysvol.is_dir() or not old_sysvol.resolve().is_relative_to(live.resolve()):
            raise TransitionError('SYSVOL original fora da árvore padrão; ajuste a instalação antes da conversão.')
        run(['smbclient', '//' + request['primary_hostname'] + '/sysvol',
             '--client-protection=sign', '-c', 'ls'] + credentials(request))
        run(['systemctl', 'stop', active[0]])
        stopped = True
        shutil.copytree(live, backup / 'rodc-state', copy_function=shutil.copy2, symlinks=True)
        attempted_demote = True
        run(['samba-tool', 'domain', 'demote', '--server=' + request['primary_hostname']] + credentials(request))
        demoted = True
        # A minimal bootstrap avoids inheriting read-only service settings.
        bootstrap = backup / 'join-bootstrap.conf'
        workgroup = run(['testparm', '-s', '--parameter-name=workgroup']).strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', workgroup):
            raise TransitionError('Workgroup NetBIOS inválido.')
        write_file(bootstrap, '[global]\n realm = ' + request['realm'] + '\n workgroup = ' + workgroup + '\n')
        run(['samba-tool', 'domain', 'join', request['realm'], 'DC',
             '--server=' + request['primary_hostname'], '--option=netbios name = ' + request['target_name'],
             '--dns-backend=SAMBA_INTERNAL', '--option=ad dc functional level = 2016', '--targetdir=' + str(stage), '-s', str(bootstrap)] + credentials(request))
        generated = stage / 'etc/smb.conf'
        if not generated.is_file() or not (stage / 'private/sam.ldb').is_file():
            raise TransitionError('Novo ingresso não produziu base/configuração válidas.')
        new_sysvol = Path(run(['testparm', '-s', '--section-name=sysvol', '--parameter-name=path', str(generated)]).strip())
        if not new_sysvol.resolve().is_relative_to(stage.resolve()):
            raise TransitionError('SYSVOL gerado fora da árvore de ingresso.')
        new_sysvol.mkdir(parents=True, exist_ok=True)
        if any(char in str(new_sysvol) for char in [';', '"', "'"]):
            raise TransitionError('Caminho SYSVOL inválido para sincronização SMB.')
        run(['smbclient', '//' + request['primary_hostname'] + '/sysvol', '--client-protection=sign',
             '-c', 'recurse ON; prompt OFF; lcd ' + str(new_sysvol) + '; mget *'] + credentials(request))
        run(['testparm', '-s', str(generated)])
        run(['samba-tool', 'dbcheck', '--cross-ncs', '-s', str(generated)])
        os.chmod(stage, 0o755)
        write_file(generated, rewrite_paths(generated.read_text(), stage, live))
        os.replace(live, previous)
        os.replace(stage, live)
        installed = True
        write_file(config, (live / 'etc/smb.conf').read_text())
        kerberos = live / 'private/krb5.conf'
        if not kerberos.is_file():
            raise TransitionError('Novo ingresso sem configuração Kerberos.')
        write_file(root / 'etc/krb5.conf', kerberos.read_text(), 0o644)
        if root == Path('/') and shutil.which('restorecon'):
            run(['restorecon', '-R', str(live), str(config)])
        run(['samba-tool', 'ntacl', 'sysvolreset'])
        run(['samba-tool', 'gpo', 'aclcheck', '-H', 'ldap://' + request['primary_hostname']] + credentials(request))
        run(['systemctl', 'start', active[0]])
        observed = run(['samba-tool', 'computer', 'show', request['target_name']])
        if not writable(observed):
            raise TransitionError('O novo DC não foi confirmado como gravável.')
        run(['samba-tool', 'drs', 'kcc', request['target_hostname']] + credentials(request))
        for attempt in range(12):
            try:
                healthy_replication(request, request['target_hostname'], run)
                break
            except (TransitionError, ValueError):
                if attempt == 11:
                    raise
                time.sleep(3)
        if fsmo(request, request['primary_hostname'], run).get('pdc') != request['primary_name']:
            raise TransitionError('O principal mudou durante a operação; verifique FSMO.')
        return ['RODC convertido por despromoção e novo ingresso como DC gravável secundário.',
                'Backup prévio: ' + str(backup), 'Base RODC anterior: ' + str(previous),
                'SAMBA_INTERNAL e replicação de entrada validados; principal preservado.']
    except Exception as error:
        if attempted_demote:
            for unit in active:
                try:
                    run(['systemctl', 'stop', unit])
                except Exception:
                    pass
            # After demotion the old replica identity is invalid. Never start it again.
            raise TransitionError(str(error) + '; despromoção do RODC já iniciada. Serviço mantido parado; não reinicie a base antiga. '
                                  'Retome o ingresso como DC. Backup: ' + str(backup) + '; árvore de trabalho: ' + str(live if installed else stage)) from error
        if stopped:
            run(['systemctl', 'start', active[0]])
        raise
    finally:
        if not attempted_demote and stage.exists():
            shutil.rmtree(stage)


def execute(request):
    if request['action'] == 'promote_primary':
        return promote_primary(request)
    if request['action'] == 'promote_writable':
        return promote_writable(request)
    raise TransitionError('Transição desconhecida.')


def main():
    request = {}
    try:
        request = json.load(sys.stdin)
        steps = execute(request)
        print(json.dumps({'success': True, 'steps': steps}, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'success': False, 'error': str(error).replace(request.get('admin_password', '') or '\0', '[REDACTED]')}, ensure_ascii=False))
        sys.exit(1)


if __name__ == '__main__':
    main()
