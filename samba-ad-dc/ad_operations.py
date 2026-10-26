#!/usr/bin/env python3
"""Transactional Samba recovery and loopback-only recursive BIND configuration."""
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


def validate_archive(path):
    if path.is_symlink() or not path.is_file():
        raise OperationError('Backup deve ser um arquivo regular, sem link simbólico.')
    with tarfile.open(path, 'r:*') as archive:
        names = set()
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or member.isdev() or member.isfifo():
                raise OperationError('Backup contém caminho ou tipo de arquivo inseguro.')
            if member.issym() or member.islnk():
                target = PurePosixPath(member.linkname)
                if target.is_absolute() or '..' in target.parts:
                    raise OperationError('Backup contém link fora da árvore de recuperação.')
            names.add(str(name))
        if not {'backup.txt', 'etc/smb.conf', 'sysvol.tar.gz'} <= names:
            raise OperationError('Use backup de domínio Samba completo, com backup.txt, smb.conf e SYSVOL.')
        if not any(name.startswith('private/sam.ldb') for name in names):
            raise OperationError('Backup não contém a base de domínio sam.ldb.')
        metadata = archive.extractfile(next(member for member in archive.getmembers() if str(PurePosixPath(member.name)) == 'backup.txt'))
        if metadata and b'contains domain secrets: False' in metadata.read(65536):
            raise OperationError('Backup sem segredos de domínio não é aceito para este fluxo.')


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
        from provision_system import install_dependencies
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


def tune_restored_config(text, stage, live):
    text = text.replace(str(stage), str(live))
    # Samba owns AD DNS; remove any inherited service list which disables DNS.
    text = re.sub(r'^\s*(dns forwarder|server services)\s*=.*$', '', text, flags=re.M | re.I)
    return re.sub(r'(?im)^\s*\[global\]\s*$', '[global]\n    dns forwarder = 127.0.0.1:5353', text, count=1)


def restore_domain(request, root=Path('/'), run=checked_run):
    filename = request['filename']
    if not filename or Path(filename).name != filename or '\\' in filename or filename.startswith('.'):
        raise OperationError('Nome de backup inválido.')
    server = request['new_server_name'].strip().upper()
    if not re.fullmatch(r'[A-Z0-9][A-Z0-9-]{0,14}', server):
        raise OperationError('Nome NetBIOS deve ter até 15 letras, números ou hífens.')
    ipaddress.IPv4Address(request['host_ip'])
    archive = root / 'var/backups/samba' / filename
    validate_archive(archive)
    live = root / 'var/lib/samba'
    config = root / 'etc/samba/smb.conf'
    kerberos = root / 'etc/krb5.conf'
    existing = (live / 'private/sam.ldb').exists() or config.exists()
    if existing and not request.get('replace_existing'):
        raise OperationError('Já existe configuração Samba. Confirme explicitamente a substituição ou use outro host.')
    if not request.get('isolated_recovery_confirmed'):
        raise OperationError('Confirme que os DCs do domínio original estão desligados/isolados para recuperar o domínio.')
    plan = [f'Recuperar domínio de {filename} como {server}, IP {request["host_ip"]}.',
            'Validar arquivo, restaurar em diretório separado e verificar banco/configuração.',
            'Preservar base anterior, ativar SAMBA_INTERNAL e BIND em loopback; reverter em caso de falha.']
    if request.get('dry_run'):
        return ['[SIMULAÇÃO] ' + step for step in plan]
    live.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='samba.restore-', dir=live.parent))
    recovery_id = uuid.uuid4().hex
    previous = live.with_name('samba.pre-restore-' + recovery_id)
    failed = live.with_name('samba.failed-restore-' + recovery_id)
    config_before = config.read_bytes() if config.exists() else None
    krb_before = kerberos.read_bytes() if kerberos.exists() else None
    active_services = []
    moved = installed = stopping = False
    try:
        run(['samba-tool', 'domain', 'backup', 'restore', '--backup-file=' + str(archive),
             '--targetdir=' + str(stage), '--newservername=' + server, '--host-ip=' + request['host_ip']])
        os.chmod(stage, 0o755)  # SYSVOL clients must be able to traverse the data-tree root.
        restored_conf = stage / 'etc/smb.conf'
        if not restored_conf.is_file() or not (stage / 'private/sam.ldb').is_file():
            raise OperationError('Samba não produziu configuração/base restaurada válida.')
        run(['testparm', '-s', str(restored_conf)])
        run(['samba-tool', 'dbcheck', '--cross-ncs', '-s', str(restored_conf)])
        # Configure the isolated recursive resolver before touching the live Samba DB.
        configure_bind({'forwarders': request.get('forwarders', ['8.8.8.8', '1.1.1.1'])}, root, run)
        for service in ['samba', 'samba-dc', 'samba-ad-dc']:
            try:
                if run(['systemctl', 'is-active', service]).strip() == 'active':
                    active_services.append(service)
            except OperationError:
                pass
        service = active_services[0] if active_services else request.get('samba_service', 'samba')
        if not active_services:
            for candidate in ['samba', 'samba-dc', 'samba-ad-dc']:
                try:
                    if run(['systemctl', 'show', '--property=LoadState', '--value', candidate]).strip() == 'loaded':
                        service = candidate
                        break
                except OperationError:
                    pass
        if service not in ['samba', 'samba-dc', 'samba-ad-dc']:
            raise OperationError('Serviço Samba inválido.')
        if config_before is not None:
            atomic_write(config.with_name('smb.conf.pre-restore-' + recovery_id), config_before)
        if krb_before is not None:
            atomic_write(kerberos.with_name('krb5.conf.pre-restore-' + recovery_id), krb_before)
        stopping = True
        for unit in set(active_services + [service]):
            run(['systemctl', 'stop', unit])
        if live.exists():
            os.replace(live, previous)
            moved = True
        atomic_write(restored_conf, tune_restored_config(restored_conf.read_text(), stage, live))
        os.replace(stage, live)
        installed = True
        atomic_write(config, (live / 'etc/smb.conf').read_text())
        krb = live / 'private/krb5.conf'
        if krb.is_file():
            krb_text = krb.read_text()
        else:
            realm = re.search(r'(?im)^\s*realm\s*=\s*([A-Za-z0-9.-]+)\s*$', config.read_text())
            if not realm:
                raise OperationError('Realm não identificado na configuração recuperada.')
            krb_text = '[libdefaults]\n    default_realm = ' + realm[1].upper() + '\n    dns_lookup_realm = false\n    dns_lookup_kdc = true\n'
        atomic_write(kerberos, krb_text, 0o644)
        if shutil.which('restorecon') and root == Path('/'):
            run(['restorecon', '-R', str(live), str(config)])
        run(['samba-tool', 'ntacl', 'sysvolreset', '-s', str(config)])
        run(['testparm', '-s', str(config)])
        run(['systemctl', 'start', service])
        if run(['systemctl', 'is-active', service]).strip() != 'active':
            raise OperationError('Samba não ficou ativo após recuperação.')
        run(['samba-tool', 'domain', 'level', 'show', '-s', str(config)])
        run(['systemctl', 'enable', service])
        return plan + [f'Domínio recuperado. Estado anterior preservado em {previous}.',
                       'Interfaces, IP, rotas e resolv.conf do host não foram alterados.']
    except Exception as error:
        failures = []
        if stopping:
            try:
                for unit in set(active_services + [service]):
                    run(['systemctl', 'stop', unit])
                if installed:
                    os.replace(live, failed)
                if moved:
                    os.replace(previous, live)
                for path, before in [(config, config_before), (kerberos, krb_before)]:
                    if before is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, before.decode(), 0o644 if path == kerberos else 0o600)
                for unit in active_services:
                    run(['systemctl', 'start', unit])
            except Exception as failure:
                failures.append(str(failure))
        suffix = '; rollback falhou: ' + '; '.join(failures) if failures else '; base anterior preservada/restaurada'
        raise OperationError(str(error) + suffix) from error
    finally:
        if stage.exists():
            shutil.rmtree(stage)


# Executed on the selected controller, never on a guessed server. Credentials
# arrive on stdin and are neither logged nor included in the SSH command.
DEMOTE_PROGRAM = r'''import json, re, subprocess, sys
request = json.load(sys.stdin)
def run(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-2000:])
    return result.stdout
try:
    name = run(['testparm', '-s', '--parameter-name=netbios name']).strip().upper()
    if name != request['target_name']:
        raise RuntimeError('Servidor SSH não corresponde ao DC selecionado.')
    fsmo = run(['samba-tool', 'fsmo', 'show']).upper()
    if ('CN=NTDS SETTINGS,CN=' + name + ',') in fsmo:
        raise RuntimeError('DC ainda possui funções FSMO; despromoção bloqueada.')
    run(['samba-tool', 'domain', 'demote', '--server=' + request['primary_hostname'],
         '-U' + request['admin_username'], '--password=' + request['admin_password']])
    for unit in ['samba', 'samba-dc', 'samba-ad-dc']:
        state = subprocess.run(['systemctl', 'is-active', unit], text=True, capture_output=True)
        if state.returncode == 0 and state.stdout.strip() == 'active':
            run(['systemctl', 'stop', unit])
    print(json.dumps({'success': True}))
except Exception as error:
    print(json.dumps({'success': False, 'error': str(error)}))
    sys.exit(1)
'''


def demote_controller(request):
    for key in ['target_hostname', 'primary_hostname', 'target_name']:
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*', request.get(key, '')):
            raise OperationError('Nome de controlador inválido.')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', request.get('ssh_user', 'root')):
        raise OperationError('Usuário SSH inválido.')
    if request.get('local'):
        command = ['python3', '-c', DEMOTE_PROGRAM]
    else:
        import shlex
        remote = ['python3', '-c', DEMOTE_PROGRAM]
        if request['ssh_user'] != 'root':
            remote = ['sudo', '-n', '--'] + remote
        command = ['ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10',
                   request['ssh_user'] + '@' + request['target_hostname'], shlex.join(remote)]
    result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, timeout=360)
    try:
        response = json.loads(result.stdout)
    except ValueError as error:
        raise OperationError('Falha de conexão ao DC. Configure chave SSH e host conhecido; para usuário não root, sudo sem senha é necessário. ' + result.stderr[-1000:]) from error
    if result.returncode or not response.get('success'):
        raise OperationError(response.get('error', 'Despromoção falhou.'))
    return ['DC secundário despromovido pelo Samba com validação de identidade e FSMO.',
            'A conta de computador remanescente pode ser excluída após atualizar a lista.']


def transition_controller(request):
    import shlex
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', request.get('ssh_user', 'root')):
        raise OperationError('Usuário SSH inválido.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', request.get('target_hostname', '')):
        raise OperationError('Hostname de destino inválido.')
    program = Path(__file__).with_name('dc_lifecycle.py').read_text()
    if request.get('local'):
        command = ['python3', '-c', program]
    else:
        remote = ['python3', '-c', program]
        if request['ssh_user'] != 'root':
            remote = ['sudo', '-n', '--'] + remote
        command = ['ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10',
                   request['ssh_user'] + '@' + request['target_hostname'], shlex.join(remote)]
    result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, timeout=3600)
    try:
        response = json.loads(result.stdout)
    except ValueError as error:
        raise OperationError('Falha de conexão/transição no DC: ' + result.stderr[-2000:]) from error
    if result.returncode or not response.get('success'):
        raise OperationError(response.get('error', 'Transição não concluída.'))
    if request['action'] == 'promote_primary' and not request.get('dry_run'):
        # Fallback only: live FSMO queries remain authoritative.
        state = Path('/var/lib/astral-ad-dns/primary-dc.json')
        atomic_write(state, json.dumps({'name': request['target_name'], 'hostname': request['target_hostname']}))
    return response.get('steps', [])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['restore', 'bind', 'demote', 'transition', 'forensic', 'provision'])
    parser.add_argument('--request')
    parser.add_argument('--request-stdin', action='store_true')
    args = parser.parse_args()
    try:
        request = json.load(sys.stdin) if args.request_stdin else json.loads(args.request)
        if args.operation == 'forensic':
            from ad_forensics import execute
            if request.get('action', 'capture') == 'capture':
                lock_path = Path('/run/lock/astral-ad-forensics.lock')
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                with lock_path.open('a') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    data = execute(request)
            else:
                data = execute(request)
            print(json.dumps({'success': True, 'data': data}, ensure_ascii=False))
            return
        lock_path = Path('/run/lock/astral-ad-operations.lock')
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == 'provision':
                if request.get('kind') == 'new':
                    from provision_dc1 import execute
                else:
                    from provision_workflow import execute
                data = execute(request)
                print(json.dumps({'success': True, 'data': data}, ensure_ascii=False))
                return
            steps = {'restore': restore_domain, 'bind': configure_bind, 'demote': demote_controller, 'transition': transition_controller}[args.operation](request)
        print(json.dumps({'success': True, 'steps': steps}, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'success': False, 'error': str(error)}, ensure_ascii=False))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
