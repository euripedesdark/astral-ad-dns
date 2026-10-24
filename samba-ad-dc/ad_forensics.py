#!/usr/bin/env python3
"""Read-only AD evidence capture, GUID-based comparison and escaped HTML5 reports.
Methodology: Euripedes Batista de Paiva Junior, Practical Guide: Manual AD Forensic Analysis.
"""
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import uuid

STORE = Path('/var/lib/astral-ad-dns/forensics')
SOURCE = 'https://medium.com/meetcyber/practical-guide-manual-active-directory-forensic-analysis-windows-and-samba-ad-1af8ac4f0623'
# Deliberately exclude unicodePwd, supplementalCredentials, histories and key material.
ATTRIBUTES = ['objectGUID', 'objectSid', 'objectClass', 'sAMAccountName', 'displayName', 'userPrincipalName',
              'userAccountControl', 'adminCount', 'member', 'memberOf', 'primaryGroupID', 'nTSecurityDescriptor',
              'whenCreated', 'whenChanged', 'pwdLastSet', 'lastLogonTimestamp', 'isDeleted',
              'gPCFileSysPath', 'gPCMachineExtensionNames', 'gPCUserExtensionNames', 'versionNumber', 'flags',
              'dNSHostName', 'dnsRecord', 'dnsProperty', 'fSMORoleOwner', 'msDS-AllowedToDelegateTo',
              'msDS-AllowedToActOnBehalfOfOtherIdentity', 'servicePrincipalName', 'sIDHistory']
BINARY_HASH = {'ntsecuritydescriptor', 'dnsrecord', 'dnsproperty', 'msds-allowedtoactonbehalfofotheridentity'}
CRITICAL = {'ntsecuritydescriptor', 'member', 'memberof', 'admincount', 'useraccountcontrol', 'primarygroupid',
            'fsmoroleowner', 'msds-allowedtodelegateto', 'msds-allowedtoactonbehalfofotheridentity', 'sidhistory'}
PRIVILEGED_RIDS = {'512', '516', '518', '519', '520', '521', '526', '527'}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = data.encode() if isinstance(data, str) else data
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(payload)
        file.flush()
        os.fsync(file.fileno())


def write_json(path, value):
    write(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def run_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Tempo limite na coleta de ' + args[0]) from error
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-2000:])
    if len(result.stdout.encode()) > 64 * 1024 * 1024:
        raise RuntimeError('Saída excede 64 MiB; coleta marcada incompleta.')
    return result.stdout


def sid_text(raw):
    if len(raw) < 8 or len(raw) < 8 + 4 * raw[1]:
        raise ValueError('SID binário inválido')
    return 'S-' + str(raw[0]) + '-' + str(int.from_bytes(raw[2:8], 'big')) + ''.join('-' + str(struct.unpack_from('<I', raw, 8 + 4 * index)[0]) for index in range(raw[1]))


def parse_ldif(text):
    unfolded = []
    for line in text.splitlines():
        if line.startswith(' ') and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    records, current = [], {}
    for line in unfolded + ['']:
        if not line.strip():
            if current.get('dn'):
                records.append(current)
            current = {}
            continue
        if line.startswith('#') or ':' not in line:
            continue
        key, rest = line.split(':', 1)
        key = key.lower()
        if rest.startswith('<'):
            raise ValueError('LDIF com referência externa não é aceito')
        if rest.startswith(':'):
            raw = base64.b64decode(rest[1:].strip(), validate=True)
            if key == 'objectguid':
                value = str(uuid.UUID(bytes_le=raw))
            elif key in ['objectsid', 'sidhistory']:
                value = sid_text(raw)
            elif key in BINARY_HASH:
                value = 'sha256:' + digest(raw)
            else:
                try:
                    value = raw.decode('utf-8')
                except UnicodeDecodeError:
                    value = 'sha256:' + digest(raw)
        else:
            value = rest.lstrip()
            if key in BINARY_HASH:
                value = 'sha256:' + digest(value.encode())
        current.setdefault(key, []).append(value)
    return [{key: sorted(set(values)) for key, values in record.items()} for record in records]


def first(record, key, default=''):
    return (record.get(key, []) or [default])[0]


def identity(record):
    return ('guid:' + first(record, 'objectguid').lower()) if record.get('objectguid') else ('dn:' + first(record, 'dn').casefold())


def ad_time(value):
    if not value or value in ['0', '9223372036854775807']:
        return 'Não definido / nunca'
    try:
        if value.isdigit():
            return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value) // 10)).isoformat()
        for pattern in ['%Y%m%d%H%M%S.%fZ', '%Y%m%d%H%M%SZ']:
            try:
                return datetime.strptime(value, pattern).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                pass
    except (ValueError, OverflowError):
        pass
    return value


def privileged(objects):
    by_dn = {first(record, 'dn').casefold(): record for record in objects.values()}
    groups = set()
    for dn, record in by_dn.items():
        sid = first(record, 'objectsid')
        if sid in {'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551'} or (sid.startswith('S-1-5-21-') and sid.rsplit('-', 1)[-1] in PRIVILEGED_RIDS):
            groups.add(dn)
    members = set(groups)
    pending = list(groups)
    while pending:
        record = by_dn.get(pending.pop(), {})
        for member in record.get('member', []):
            normalized = member.casefold()
            if normalized not in members:
                members.add(normalized)
                if 'group' in [value.lower() for value in by_dn.get(normalized, {}).get('objectclass', [])]:
                    pending.append(normalized)
    accounts = []
    for key, record in objects.items():
        classes = {value.lower() for value in record.get('objectclass', [])}
        if 'user' not in classes and 'computer' not in classes:
            continue
        reasons = []
        if first(record, 'admincount') == '1':
            reasons.append('adminCount=1 (marcador histórico)')
        if first(record, 'dn').casefold() in members or any(dn.casefold() in members for dn in record.get('memberof', [])):
            reasons.append('Associação direta/indireta a grupo privilegiado')
        if first(record, 'primarygroupid') in PRIVILEGED_RIDS:
            reasons.append('Grupo primário privilegiado')
        if reasons:
            flags = int(first(record, 'useraccountcontrol', '0'))
            accounts.append({'id': key, 'dn': first(record, 'dn'), 'account': first(record, 'samaccountname'),
                             'disabled': bool(flags & 2), 'password_never_expires': bool(flags & 0x10000),
                             'last_change': first(record, 'whenchanged'), 'last_logon': first(record, 'lastlogontimestamp'),
                             'last_change_utc': ad_time(first(record, 'whenchanged')), 'last_logon_utc': ad_time(first(record, 'lastlogontimestamp')),
                             'password_set_utc': ad_time(first(record, 'pwdlastset')),
                             'reasons': reasons})
    return sorted(accounts, key=lambda account: account['dn'].casefold())


def compare(old, new):
    result = {'available': False, 'reason': '', 'added': [], 'removed': [], 'modified': [], 'sysvol': [],
              'summary': {'added': 0, 'removed': 0, 'modified': 0, 'disabled_accounts': 0, 'permissions_changed': 0,
                          'privileged_changed': 0, 'gpo_changed': 0, 'dns_changed': 0, 'sysvol_changed': 0}}
    if not old:
        result['reason'] = 'Primeira captura: inventário de referência. Capture novamente para comparar.'
        return result
    if not old.get('objects_complete') or not new.get('objects_complete'):
        result['reason'] = 'Coleta de objetos incompleta em uma captura; diferenças não inferidas.'
        return result
    if not old.get('domain_sid') or old['domain_sid'] != new.get('domain_sid') or old.get('realm') != new.get('realm') or old.get('host') != new.get('host') or old.get('naming_contexts') != new.get('naming_contexts'):
        result['reason'] = 'Identidade/host/escopo de domínio divergente ou não confirmado; comparação bloqueada.'
        return result
    result['available'] = True
    previous, current = old['objects'], new['objects']
    privileged_ids = {account['id'] for account in privileged(previous) + privileged(current)}
    for key in sorted(set(previous) | set(current)):
        before, after = previous.get(key), current.get(key)
        kind = 'added' if before is None else 'removed' if after is None else 'modified'
        record = after or before
        if kind == 'modified':
            changes = {name: {'before': before.get(name, []), 'after': after.get(name, [])}
                       for name in set(before) | set(after) if before.get(name, []) != after.get(name, [])}
            if not changes:
                continue
        else:
            changes = {}
        critical = key in privileged_ids or bool(set(changes) & CRITICAL)
        item = {'id': key, 'dn': first(record, 'dn'), 'previous_dn': first(before or {}, 'dn'),
                'account': first(record, 'samaccountname'), 'severity': 'critical' if critical else 'review',
                'changes': changes, 'privileged': key in privileged_ids}
        result[kind].append(item)
        result['summary'][kind] += 1
        classes = {value.lower() for value in record.get('objectclass', [])}
        if key in privileged_ids:
            result['summary']['privileged_changed'] += 1
        if 'grouppolicycontainer' in classes:
            result['summary']['gpo_changed'] += 1
        if classes & {'dnszone', 'dnsnode'}:
            result['summary']['dns_changed'] += 1
        if 'ntsecuritydescriptor' in changes:
            result['summary']['permissions_changed'] += 1
        if before and after and 'useraccountcontrol' in changes:
            old_flags, new_flags = int(first(before, 'useraccountcontrol', '0')), int(first(after, 'useraccountcontrol', '0'))
            if not old_flags & 2 and new_flags & 2:
                result['summary']['disabled_accounts'] += 1
    if old.get('sysvol_complete') and new.get('sysvol_complete'):
        for path in sorted(set(old.get('sysvol', {})) | set(new.get('sysvol', {}))):
            a, b = old.get('sysvol', {}).get(path), new.get('sysvol', {}).get(path)
            if a != b:
                result['sysvol'].append({'path': path, 'before': a, 'after': b})
        result['summary']['sysvol_changed'] = len(result['sysvol'])
    else:
        result['sysvol_reason'] = 'SYSVOL incompleto; alterações de arquivos/ACLs não inferidas.'
    return result


def collect_sysvol(root, acl_text):
    acl_blocks = {}
    for block in acl_text.split('\n\n'):
        file_line = next((line[8:] for line in block.splitlines() if line.startswith('# file: ')), None)
        if file_line:
            path = Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), file_line))
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                continue
            acl_blocks[relative] = digest('\n'.join(line for line in block.splitlines() if not line.startswith('# file: ')).encode())
    entries, errors = {}, []
    def on_error(error):
        errors.append(str(error))
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=on_error):
        for path in [Path(directory)] + [Path(directory) / name for name in files] + [Path(directory) / name for name in dirs if (Path(directory) / name).is_symlink()]:
            try:
                metadata = path.lstat()
                item = {'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid, 'gid': metadata.st_gid,
                        'posix_acl_sha256': acl_blocks.get(path.relative_to(root).as_posix())}
                if not path.is_symlink() and item['posix_acl_sha256'] is None:
                    errors.append('ACL POSIX não capturada: ' + str(path))
                if path.is_symlink():
                    item['symlink'] = os.readlink(path)
                elif path.is_file():
                    checksum = hashlib.sha256()
                    with path.open('rb') as file:
                        for chunk in iter(lambda: file.read(1024 * 1024), b''):
                            checksum.update(chunk)
                    item['content_sha256'] = checksum.hexdigest()
                    after_read = path.stat()
                    if after_read.st_mtime_ns != metadata.st_mtime_ns or after_read.st_size != metadata.st_size:
                        errors.append('Arquivo mudou durante a captura: ' + str(path))
                try:
                    item['ntacl_sha256'] = digest(os.getxattr(path, 'security.NTACL', follow_symlinks=False))
                except OSError as error:
                    if error.errno not in [61, 93, 95]:
                        errors.append(str(error))
                entries[path.relative_to(root).as_posix()] = item
            except OSError as error:
                errors.append(str(error))
    return entries, errors


def manifest(directory):
    return {path.name: digest(path.read_bytes()) for path in directory.iterdir() if path.is_file() and path.name != 'manifest.json'}


def verify(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Registro de evidência inexistente ou inválido.')
    expected = json.loads((directory / 'manifest.json').read_text())
    if expected != manifest(directory):
        raise ValueError('Integridade SHA-256 diverge do manifesto; evidência não utilizada.')
    return expected


def safe_id(value, prefix):
    if not re.fullmatch(prefix + r'_[a-f0-9]{32}', value or ''):
        raise ValueError('Identificador de evidência inválido.')
    return value


def load_snapshot(identifier, store=STORE):
    directory = store / 'snapshots' / safe_id(identifier, 'snp')
    verify(directory)
    return json.loads((directory / 'snapshot.json').read_text())


def capture(request, store=STORE, run=run_command):
    identifier = 'snp_' + uuid.uuid4().hex
    parent = store / 'snapshots'
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = parent / ('.capture-' + identifier)
    staging.mkdir(mode=0o700)
    snapshot = {'id': identifier, 'started_at': now(), 'analyst': request.get('analyst', ''), 'label': request.get('label', '')[:240],
                'objects': {}, 'objects_complete': False, 'sysvol': {}, 'sysvol_complete': False, 'checks': [],
                'naming_contexts': [], 'domain_sid': '', 'host': '', 'realm': ''}
    def collect(name, args, filename=None):
        started = now()
        try:
            output = run(args)
            if filename:
                write(staging / filename, output)
            snapshot['checks'].append({'name': name, 'status': 'collected', 'started_at': started, 'finished_at': now(), 'command': args})
            return output
        except Exception as error:
            snapshot['checks'].append({'name': name, 'status': 'unavailable', 'message': str(error)[-2000:], 'started_at': started, 'finished_at': now(), 'command': args})
            return None
    snapshot['host'] = (collect('Host de coleta', ['hostname', '-f']) or '').strip()
    snapshot['realm'] = (collect('Realm', ['testparm', '-s', '--parameter-name=realm']) or '').strip().upper()
    snapshot['software'] = {
        'kernel': (collect('Versão do sistema', ['uname', '-srm'], 'system-version.txt') or '').strip(),
        'samba': (collect('Versão Samba', ['samba-tool', '--version'], 'samba-version.txt') or '').strip(),
        'ldb': (collect('Versão LDB', ['ldbsearch', '--version'], 'ldb-version.txt') or '').strip(),
    }
    private = (collect('Diretório privado Samba', ['testparm', '-s', '--parameter-name=private dir']) or '').strip()
    if private and Path(private).is_absolute():
        database = str(Path(private) / 'sam.ldb')
        root_ldif = collect('Contextos de diretório', ['ldbsearch', '-H', database, '--option=dsdb:schema cache dir=' + private, '-b', '', '-s', 'base', 'namingContexts', 'defaultNamingContext'], 'rootdse.ldif')
        try:
            root = parse_ldif(root_ldif or '')
            # RootDSE has an empty DN, so parse its attributes separately.
            if not root:
                root = parse_ldif('dn: rootDSE\n' + (root_ldif or ''))
            contexts = sorted({context for record in root for context in record.get('namingcontexts', [])})
            default_dn = next((first(record, 'defaultnamingcontext') for record in root if record.get('defaultnamingcontext')), '')
            snapshot['naming_contexts'] = contexts
            complete = bool(contexts)
            for index, context in enumerate(contexts):
                output = collect('Objetos: ' + context, ['ldbsearch', '-H', database, '--option=dsdb:schema cache dir=' + private, '-b', context, '-s', 'sub', '(objectClass=*)'] + ATTRIBUTES, f'objects-{index:03d}.ldif')
                if output is None:
                    complete = False
                    continue
                for record in parse_ldif(output):
                    snapshot['objects'][identity(record)] = record
                    if first(record, 'dn').casefold() == default_dn.casefold():
                        snapshot['domain_sid'] = first(record, 'objectsid')
            snapshot['objects_complete'] = complete and bool(snapshot['objects']) and bool(snapshot['domain_sid'])
        except Exception as error:
            snapshot['checks'].append({'name': 'Decodificação LDIF', 'status': 'unavailable', 'message': str(error)})
    collect('Zonas DNS (ferramenta nativa)', ['samba-tool', 'dns', 'zonelist', 'localhost', '-P'], 'dns-zones.txt')
    collect('Políticas de grupo', ['samba-tool', 'gpo', 'listall', '-P'], 'gpos.txt')
    collect('Funções FSMO', ['samba-tool', 'fsmo', 'show'], 'fsmo.txt')
    collect('Replicação DRS', ['samba-tool', 'drs', 'showrepl', '--json', '-P'], 'replication.json')
    clock = collect('Sincronização de horário', ['timedatectl', 'show', '--property=NTPSynchronized', '--value'], 'time-sync.txt')
    snapshot['clock_synchronized'] = (clock or '').strip().lower() == 'yes'
    collect('Referência de relógio Chrony', ['chronyc', 'tracking'], 'chrony.txt')
    sysvol = (collect('Caminho SYSVOL', ['testparm', '-s', '--section-name=sysvol', '--parameter-name=path']) or '').strip()
    if sysvol and Path(sysvol).is_dir() and not Path(sysvol).is_symlink():
        acl = collect('ACLs POSIX SYSVOL', ['getfacl', '-R', '-P', '-p', '-n', sysvol], 'sysvol-posix.acl')
        entries, errors = collect_sysvol(Path(sysvol), acl or '')
        snapshot['sysvol'] = entries
        snapshot['sysvol_complete'] = acl is not None and not errors
        for error in errors:
            snapshot['checks'].append({'name': 'Arquivo/NTACL SYSVOL', 'status': 'unavailable', 'message': error})
    else:
        snapshot['checks'].append({'name': 'SYSVOL', 'status': 'unavailable', 'message': 'Caminho ausente/inacessível ou link simbólico.'})
    snapshot['object_count'] = len(snapshot['objects'])
    snapshot['sysvol_item_count'] = len(snapshot['sysvol'])
    snapshot['finished_at'] = now()
    snapshot['status'] = 'complete' if snapshot['objects_complete'] and snapshot['sysvol_complete'] and all(check['status'] == 'collected' for check in snapshot['checks']) else 'partial'
    write_json(staging / 'snapshot.json', snapshot)
    write_json(staging / 'manifest.json', manifest(staging))
    os.replace(staging, parent / identifier)
    return snapshot


def display(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value
    return html.escape(text[:12000] + (' [exibição truncada; dados completos no JSON]' if len(text) > 12000 else ''))


def table(headers, rows):
    if not rows:
        return '<p class="muted">Nenhum item observado nesta seção.</p>'
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + display(header) + '</th>' for header in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + display(cell) + '</td>' for cell in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def render_html(report):
    current, comparison = report['snapshot'], report['comparison']
    summary = comparison['summary']
    cards = ''.join('<div class="card"><strong>' + str(summary[key]) + '</strong><span>' + title + '</span></div>' for key, title in [
        ('added', 'Adicionados'), ('removed', 'Removidos / não observados'), ('modified', 'Modificados'), ('disabled_accounts', 'Novas desativações'),
        ('permissions_changed', 'ACLs AD modificadas'), ('privileged_changed', 'Objetos privilegiados alterados'), ('gpo_changed', 'GPOs alteradas'), ('dns_changed', 'Objetos DNS alterados'), ('sysvol_changed', 'Itens SYSVOL alterados')])
    sections = []
    for key, title in [('removed', 'Removidos / não observados'), ('added', 'Objetos adicionados'), ('modified', 'Objetos modificados')]:
        rows = []
        for item in comparison[key]:
            rows.append([item['severity'], item['dn'], item['account'], item['changes'] if key == 'modified' else item['id']])
        sections.append('<details open><summary>' + title + '</summary>' + table(['Prioridade', 'Objeto / DN', 'Conta', 'Evidência antes/depois'], rows) + '</details>')
    inventories = table(['Conta', 'DN', 'Desabilitada', 'Senha não expira', 'Motivo do enquadramento', 'Última mudança UTC', 'Último acesso replicado UTC', 'Senha definida UTC'], [[account['account'], account['dn'], account['disabled'], account['password_never_expires'], account['reasons'], account['last_change_utc'], account['last_logon_utc'], account['password_set_utc']] for account in report['privileged_accounts']])
    checks = table(['Coleta', 'Estado', 'Detalhe'], [[check['name'], check['status'], check.get('message', '')] for check in current['checks']])
    evidence = table(['Arquivo', 'SHA-256'], [[name, value] for name, value in report['evidence_hashes'].items()])
    sysvol = table(['Caminho relativo', 'Antes', 'Depois'], [[item['path'], item['before'], item['after']] for item in comparison['sysvol']])
    warnings = ''.join('<li>' + display(warning) + '</li>' for warning in report['limitations'])
    return '''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Relatório Forense AD</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#eef2f7;color:#17243a;font:15px/1.55 system-ui,sans-serif}article{max-width:1200px;margin:auto;padding:32px}header{background:#10243a;color:white;padding:28px;border-radius:14px}h1{margin:8px 0;font-size:29px}h2{margin-top:30px;font-size:21px}.eyebrow{letter-spacing:.15em;text-transform:uppercase;color:#91e2e0;font-size:12px}.meta{color:#d6e2ed;font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:24px 0}.card{background:white;border:1px solid #dce4ee;border-radius:12px;padding:18px}.card strong{display:block;font-size:30px;color:#136f80}.card span{font-size:12px}.notice{padding:16px;background:#fff4d9;border-left:4px solid #b97500;border-radius:8px;margin:20px 0}.muted{color:#607084}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px;background:white}th,td{text-align:left;padding:10px;border:1px solid #dce4ee;vertical-align:top;overflow-wrap:anywhere;white-space:pre-wrap}th{background:#e4ebf3}details{background:white;border:1px solid #dce4ee;padding:16px;border-radius:10px;margin:12px 0}summary{font-weight:700;cursor:pointer}footer{font-size:12px;color:#607084;margin-top:30px}@media print{body{background:white}article{padding:0}header{color:#17243a;background:white;border:1px solid #dce4ee}.meta{color:#17243a}details{break-inside:auto}table{font-size:9px}header,.cards{break-inside:avoid}}
</style></head><body><article><header><div class="eyebrow">Astral · Evidências de diretório</div><h1>Relatório Forense Active Directory</h1><div class="meta">''' + display(current['realm']) + ' · ' + display(current['host']) + '</div><div class="meta">Analista: ' + display(report['analyst']) + ' · Emissão UTC: ' + display(report['created_at']) + '</div><div class="meta">Relatório: ' + display(report['id']) + ' · Captura: ' + display(current['id']) + ' · Referência: ' + display(report.get('baseline_id') or 'inventário inicial') + '</div></header><div class="notice"><strong>Estado da coleta: ' + display(current['status']) + '</strong><p>Janela UTC: ' + display(current['started_at']) + ' → ' + display(current['finished_at']) + '</p><p>' + display(comparison.get('reason') or 'Comparação por identidade estável dos objetos e atributos normalizados.') + '</p><p>Contexto: ' + display(current.get('label', '')) + '</p><p>Ambiente: ' + display(current.get('software', {})) + '</p></div><section class="cards">' + cards + '</section><h2>Objetos e alterações críticas</h2>' + ''.join(sections) + '<h2>Inventário atual de contas privilegiadas</h2>' + inventories + '<h2>Alterações de arquivos e permissões SYSVOL</h2>' + sysvol + '<p class="muted">' + display(comparison.get('sysvol_reason', 'Conteúdo, ACL POSIX e hash security.NTACL quando acessível.')) + '</p><h2>Completude e disponibilidade das coletas</h2>' + checks + '<h2>Integridade das evidências da captura atual</h2>' + evidence + '<h2>Limites e próximos passos</h2><ul>' + warnings + '</ul><footer>Metodologia baseada no guia de Euripedes Batista de Paiva Junior: Practical Guide: Manual Active Directory Forensic Analysis (Windows and Samba AD).<br>' + html.escape(SOURCE) + '</footer></article></body></html>'


def create_report(snapshot, baseline=None, store=STORE):
    identifier = 'rep_' + uuid.uuid4().hex
    evidence = verify(store / 'snapshots' / snapshot['id'])
    limitations = ['As diferenças são observações entre capturas, não comprovam autoria, comprometimento ou horário exato de exclusão.',
                   'lastLogonTimestamp é um indicador replicado aproximado; não substitui os logs de autenticação.',
                   'Coleta de domínio em execução: o intervalo não é um snapshot transacional único. Considere atraso de replicação.',
                   'Hashes SHA-256 detectam divergências locais; não equivalem a assinatura digital ou carimbo de tempo externo.',
                   'Credenciais, senhas, históricos de senha e chaves Kerberos não são coletados. Logs de segurança Windows não são consultados.',
                   'ACLs POSIX não representam sozinhas todas as permissões Windows. O hash security.NTACL é registrado quando o xattr existe; ausência não comprova ausência de ACL Windows.',
                   'Revise associações privilegiadas, ACLs e logs do período antes de decidir qualquer ação de restauração ou contenção.']
    if not snapshot['clock_synchronized']:
        limitations.insert(0, 'Sincronização NTP não confirmada; valide o relógio antes de correlacionar eventos.')
    if snapshot['status'] != 'complete':
        limitations.insert(0, 'Coleta parcial: consulte as etapas indisponíveis. Ausência de diferenças não significa ausência de alterações.')
    report = {'id': identifier, 'created_at': now(), 'analyst': snapshot['analyst'], 'baseline_id': baseline['id'] if baseline else None,
              'snapshot': {key: value for key, value in snapshot.items() if key not in ['objects', 'sysvol']},
              'comparison': compare(baseline, snapshot), 'privileged_accounts': privileged(snapshot['objects']),
              'evidence_hashes': evidence, 'limitations': limitations, 'methodology': {'author': 'Euripedes Batista de Paiva Junior', 'source': SOURCE}}
    if baseline:
        report['baseline_evidence_hashes'] = verify(store / 'snapshots' / baseline['id'])
    parent = store / 'reports'
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = parent / ('.report-' + identifier)
    directory.mkdir(mode=0o700)
    write_json(directory / 'report.json', report)
    write(directory / 'report.html', render_html(report))
    write_json(directory / 'manifest.json', manifest(directory))
    os.replace(directory, parent / identifier)
    return report


def overview(store=STORE):
    result = {'snapshots': [], 'reports': []}
    for category, filename, fields in [('snapshots', 'snapshot.json', ['id', 'started_at', 'finished_at', 'status', 'label', 'host', 'realm', 'objects_complete', 'object_count']),
                                       ('reports', 'report.json', ['id', 'created_at', 'analyst', 'baseline_id'])]:
        directory = store / category
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir(), key=lambda value: value.name, reverse=True):
            if path.name.startswith('.') or not path.is_dir() or path.is_symlink():
                continue
            try:
                verify(path)
                item = json.loads((path / filename).read_text())
                summary = {key: item.get(key) for key in fields}
                if category == 'reports':
                    summary.update({'snapshot_id': item['snapshot']['id'], 'status': item['snapshot']['status'], 'summary': item['comparison']['summary']})
                result[category].append(summary)
            except (OSError, ValueError) as error:
                result[category].append({'id': path.name, 'status': 'integrity_error', 'error': str(error)})
        result[category].sort(key=lambda value: value.get('created_at', value.get('started_at', '')), reverse=True)
    return result


def execute(request, store=STORE, run=run_command):
    os.umask(0o077)
    action = request.get('action', 'capture')
    if action == 'overview':
        return overview(store)
    if action in ['report', 'html']:
        directory = store / 'reports' / safe_id(request.get('report_id'), 'rep')
        verify(directory)
        return {'html': (directory / 'report.html').read_text()} if action == 'html' else json.loads((directory / 'report.json').read_text())
    if action == 'capture':
        baseline = load_snapshot(request['baseline_id'], store) if request.get('baseline_id') else None
        current = capture(request, store, run)
        report = create_report(current, baseline, store)
        return {'snapshot_id': current['id'], 'report_id': report['id'], 'status': current['status'], 'summary': report['comparison']['summary']}
    raise ValueError('Ação forense inválida.')
