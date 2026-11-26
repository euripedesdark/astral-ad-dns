#!/usr/bin/env python3
"""Transactional Samba recovery and loopback-only recursive BIND configuration."""
import argparse
try:
    import fcntl
except ImportError:
    fcntl = None
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
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=1800)
    except FileNotFoundError as e:
        raise OperationError(f"Comando '{args[0]}' nao encontrado no sistema") from e
    except OSError as e:
        raise OperationError(f"Falha ao executar '{args[0]}': {e}") from e
    if result.returncode:
        raise OperationError(f"{args[0]} falhou: {(result.stderr or result.stdout)[-3000:]}")
    return result.stdout


def optional(run, args):
    try:
        return run(args)
    except Exception:
        return ''


def enable_selinux_samba_dc(root=Path('/'), run=checked_run):
    """Garante que a boolean samba_domain_controller do SELinux esteja ativa para o AD DC."""
    if (root / 'sys/fs/selinux/enforce').exists():
        try:
            res = subprocess.run(['getsebool', 'samba_domain_controller'], text=True, capture_output=True)
            if res.returncode == 0 and 'off' in res.stdout:
                run(['setsebool', '-P', 'samba_domain_controller', 'on'])
        except Exception:
            pass


def ensure_samba_directories(root=Path('/')):
    """Ensure all runtime, cache, lock, and private directories expected by Samba exist.

    Debian and RHEL packages compile in paths to /var/cache/samba, /var/lib/samba,
    /var/lib/samba/private, /var/log/samba, /run/samba, and /etc/samba. If any
    are missing (e.g. after package purge or overwrite cleanup), testparm and
    samba-tool fail immediately with:
    'ERROR: cache directory /var/cache/samba does not exist'.
    """
    dirs = [
        (root / 'var/cache/samba', 0o755),
        (root / 'var/lib/samba', 0o755),
        (root / 'var/lib/samba/private', 0o700),
        (root / 'var/log/samba', 0o755),
        (root / 'run/samba', 0o755),
        (root / 'var/run/samba', 0o755),
        (root / 'etc/samba', 0o755),
    ]
    for d, mode in dirs:
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(mode)
        except OSError:
            pass


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


class DistroProfile:
    def __init__(self, family, samba_unit, samba_conflicts, bind_user, bind_group, bind_service,
                 bind_config_rel, bind_main_rel, bind_work_dir, chrony_user, chrony_group,
                 chrony_service, security_system):
        self.family = family
        self.samba_unit = samba_unit
        self.samba_conflicts = samba_conflicts
        self.bind_user = bind_user
        self.bind_group = bind_group
        self.bind_service = bind_service
        self.bind_config_rel = bind_config_rel
        self.bind_main_rel = bind_main_rel
        self.bind_work_dir = bind_work_dir
        self.bind_cache = bind_work_dir
        self.chrony_user = chrony_user
        self.chrony_group = chrony_group
        self.chrony_service = chrony_service
        self.security_system = security_system


def detect_distro_profile(root=Path('/')):
    os_release = root / 'etc/os-release'
    distro_id = ''
    id_like = ''
    if os_release.exists():
        try:
            for line in os_release.read_text(encoding='utf-8').splitlines():
                if '=' in line and not line.strip().startswith('#'):
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'").lower()
                    if k == 'ID':
                        distro_id = v
                    elif k == 'ID_LIKE':
                        id_like = v
        except OSError:
            pass
    if not distro_id:
        if (root / 'etc/debian_version').exists() or (root / 'etc/bind').is_dir():
            distro_id = 'debian'
        elif (root / 'etc/arch-release').exists():
            distro_id = 'arch'
        elif (root / 'etc/redhat-release').exists() or (root / 'etc/fedora-release').exists():
            distro_id = 'fedora'

    is_debian = distro_id in ('debian', 'ubuntu') or 'debian' in id_like or 'ubuntu' in id_like or (root / 'etc/debian_version').exists() or (root / 'etc/bind').is_dir()
    is_arch = distro_id in ('arch', 'archlinux', 'manjaro') or 'arch' in id_like or (root / 'etc/arch-release').exists()
    is_suse = distro_id in ('opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'sles', 'sled', 'suse') or 'suse' in id_like or (root / 'etc/SuSE-release').exists()

    if is_debian:
        return DistroProfile(
            family='debian',
            samba_unit='samba-ad-dc',
            samba_conflicts=['smbd', 'nmbd', 'winbind'],
            bind_user='bind',
            bind_group='bind',
            bind_service='named',
            bind_config_rel='etc/bind/named.conf.options',
            bind_main_rel='etc/bind/named.conf',
            bind_work_dir='/var/cache/bind',
            chrony_user='_chrony',
            chrony_group='_chrony',
            chrony_service='chrony',
            security_system='apparmor',
        )
    elif is_suse:
        return DistroProfile(
            family='suse',
            samba_unit='samba-ad-dc',
            samba_conflicts=['smb', 'nmb', 'winbind'],
            bind_user='named',
            bind_group='named',
            bind_service='named',
            bind_config_rel='etc/named.conf',
            bind_main_rel='etc/named.conf',
            bind_work_dir='/var/lib/named',
            chrony_user='chrony',
            chrony_group='chrony',
            chrony_service='chronyd',
            security_system='apparmor',
        )
    elif is_arch:
        return DistroProfile(
            family='arch',
            samba_unit='samba',
            samba_conflicts=['smb', 'nmb', 'winbind'],
            bind_user='named',
            bind_group='named',
            bind_service='named',
            bind_config_rel='etc/named.conf',
            bind_main_rel='etc/named.conf',
            bind_work_dir='/var/named',
            chrony_user='chrony',
            chrony_group='chrony',
            chrony_service='chronyd',
            security_system='none',
        )
    else:  # RedHat / Fedora / Alma / Rocky / CentOS / default
        return DistroProfile(
            family='redhat',
            samba_unit='samba',
            samba_conflicts=['smb', 'nmb', 'winbind'],
            bind_user='named',
            bind_group='named',
            bind_service='named',
            bind_config_rel='etc/named.conf',
            bind_main_rel='etc/named.conf',
            bind_work_dir='/var/named',
            chrony_user='chrony',
            chrony_group='chrony',
            chrony_service='chronyd',
            security_system='selinux',
        )


def bind_paths(root):
    profile = detect_distro_profile(root)
    return root / profile.bind_config_rel, root / profile.bind_main_rel, profile.bind_service, profile.bind_work_dir


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


def hybrid_options(forwarders, directory, port=5353):
    return ('options {\n'
            f'    directory "{directory}";\n'
            f'    listen-on port {port} {{ 127.0.0.1; }};\n'
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


def extract_user_zones(content):
    """Extrai declaracoes de zonas customizadas pelo usuario, ignorando zonas padrao/root."""
    clean = re.sub(r'//[^\n]*|#[^\n]*|/\*.*?\*/', lambda m: ' ' * len(m[0]), content, flags=re.S)
    zones = []
    for match in re.finditer(r'\bzone\s+"([^"]+)"\s*(?:IN)?\s*\{', clean, re.I):
        zname = match[1].strip()
        if zname.lower() in ('.', 'localhost', 'localhost.localdomain', '127.in-addr.arpa', '0.0.127.in-addr.arpa', '0.in-addr.arpa', '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa'):
            continue
        level = 1
        start_idx = match.start()
        end_idx = None
        for i in range(match.end(), len(content)):
            if content[i] == '{': level += 1
            elif content[i] == '}':
                level -= 1
                if level == 0:
                    end = i + 1
                    while end < len(content) and content[end] in ' \t\r\n;':
                        end += 1
                    end_idx = end
                    break
        if end_idx:
            zones.append(content[start_idx:end_idx].strip())
    return '\n\n'.join(zones)


def generate_distro_bind_config(family, forwarders, directory, port=5353, root=Path('/')):
    fwd_entries = ' '.join(ip + ';' for ip in forwarders)
    if family == 'debian':
        # Debian / Ubuntu: named.conf.options modular
        main_conf = root / 'etc/bind/named.conf'
        if not main_conf.exists() or not main_conf.read_text().strip():
            main_lines = [
                '// Astral AD & Hybrid DNS - BIND 9 Main Configuration (Debian / Ubuntu)',
                'include "/etc/bind/named.conf.options";',
                'include "/etc/bind/named.conf.local";',
            ]
            if (root / 'etc/bind/named.conf.default-zones').exists():
                main_lines.append('include "/etc/bind/named.conf.default-zones";')
            atomic_write(main_conf, '\n'.join(main_lines) + '\n', 0o644)
        local_conf = root / 'etc/bind/named.conf.local'
        if not local_conf.exists():
            atomic_write(local_conf, '// Astral AD & Hybrid DNS - Local configuration\n', 0o644)

        return (
            '// Astral AD & Hybrid DNS - BIND 9 Options (Debian / Ubuntu)\n'
            'options {\n'
            f'    directory "{directory}";\n'
            f'    listen-on port {port} {{ 127.0.0.1; }};\n'
            '    listen-on-v6 { none; };\n'
            '    allow-query { localhost; };\n'
            '    allow-recursion { localhost; };\n'
            '    allow-query-cache { localhost; };\n'
            '    recursion yes;\n'
            '    forward only;\n'
            f'    forwarders {{ {fwd_entries} }};\n'
            '    dnssec-validation auto;\n'
            '    auth-nxdomain no;    # conform to RFC1035\n'
            '    max-cache-size 64m;\n'
            '    minimal-responses yes;\n'
            '};\n'
        )

    elif family == 'redhat':
        # RedHat / Fedora: Monolitico /etc/named.conf com caminhos e politicas Red Hat
        crypto_file = root / 'etc/crypto-policies/back-ends/bind.config'
        crypto_inc = '    include "/etc/crypto-policies/back-ends/bind.config";\n' if crypto_file.exists() else ''
        hint_file = '/etc/named.ca' if (root / 'etc/named.ca').exists() else 'named.ca'
        geoip_line = '    geoip-directory "/usr/share/GeoIP";\n' if (root / 'usr/share/GeoIP').is_dir() else ''

        lines = [
            '// Astral AD & Hybrid DNS - BIND 9 Configuration (Fedora / RHEL)',
            'options {',
            f'    directory "{directory}";',
            '    dump-file "/var/named/data/cache_dump.db";',
            '    statistics-file "/var/named/data/named_stats.txt";',
            '    memstatistics-file "/var/named/data/named_mem_stats.txt";',
            '    secroots-file "/var/named/data/named.secroots";',
            '    recursing-file "/var/named/data/named.recursing";',
            '',
            f'    listen-on port {port} {{ 127.0.0.1; }};',
            '    listen-on-v6 { none; };',
            '',
            '    allow-query { localhost; };',
            '    allow-recursion { localhost; };',
            '    allow-query-cache { localhost; };',
            '',
            '    recursion yes;',
            '    forward only;',
            f'    forwarders {{ {fwd_entries} }};',
            '',
            '    dnssec-validation auto;',
            '    max-cache-size 64m;',
            '    minimal-responses yes;',
            '    managed-keys-directory "/var/named/dynamic";',
        ]
        if geoip_line:
            lines.append('    geoip-directory "/usr/share/GeoIP";')
        lines.extend([
            '    pid-file "/run/named/named.pid";',
            '    session-keyfile "/run/named/session.key";',
        ])
        if crypto_inc:
            lines.append('    include "/etc/crypto-policies/back-ends/bind.config";')
        lines.extend([
            '};',
            '',
            'logging {',
            '    channel default_debug {',
            '        file "data/named.run";',
            '        severity dynamic;',
            '    };',
            '};',
            '',
            'zone "." IN {',
            '    type hint;',
            f'    file "{hint_file}";',
            '};',
        ])
        if (root / 'etc/named.rfc1912.zones').exists():
            lines.append('include "/etc/named.rfc1912.zones";')
        if (root / 'etc/named.root.key').exists():
            lines.append('include "/etc/named.root.key";')
        return '\n'.join(lines) + '\n'

    elif family == 'arch':
        # Arch Linux: /etc/named.conf com run/named
        lines = [
            '// Astral AD & Hybrid DNS - BIND 9 Configuration (Arch Linux)',
            'options {',
            f'    directory "{directory}";',
            '    pid-file "/run/named/named.pid";',
            f'    listen-on port {port} {{ 127.0.0.1; }};',
            '    listen-on-v6 { none; };',
            '    allow-query { localhost; };',
            '    allow-recursion { localhost; };',
            '    allow-query-cache { localhost; };',
            '    recursion yes;',
            '    forward only;',
            f'    forwarders {{ {fwd_entries} }};',
            '    dnssec-validation auto;',
            '    max-cache-size 64m;',
            '    minimal-responses yes;',
            '};',
        ]
        if (root / 'var/named/root.hint').exists():
            lines.extend(['', 'zone "." IN {', '    type hint;', '    file "root.hint";', '};'])
        if (root / 'var/named/localhost.zone').exists():
            lines.extend(['', 'zone "localhost" IN {', '    type master;', '    file "localhost.zone";', '};'])
        if (root / 'var/named/127.0.0.zone').exists():
            lines.extend(['', 'zone "0.0.127.in-addr.arpa" IN {', '    type master;', '    file "127.0.0.zone";', '};'])
        return '\n'.join(lines) + '\n'

    elif family == 'suse':
        # openSUSE / SUSE: /var/lib/named e dump em /var/log/
        lines = [
            '// Astral AD & Hybrid DNS - BIND 9 Configuration (openSUSE / SUSE)',
            'options {',
            f'    directory "{directory}";',
            '    dump-file "/var/log/named_dump.db";',
            '    statistics-file "/var/log/named.stats";',
            f'    listen-on port {port} {{ 127.0.0.1; }};',
            '    listen-on-v6 { none; };',
            '    allow-query { localhost; };',
            '    allow-recursion { localhost; };',
            '    allow-query-cache { localhost; };',
            '    recursion yes;',
            '    forward only;',
            f'    forwarders {{ {fwd_entries} }};',
            '    dnssec-validation auto;',
            '    max-cache-size 64m;',
            '    minimal-responses yes;',
            '};',
        ]
        if (root / 'var/lib/named/root.hint').exists():
            lines.extend(['', 'zone "." in {', '    type hint;', '    file "root.hint";', '};'])
        if (root / 'var/lib/named/localhost.zone').exists():
            lines.extend(['', 'zone "localhost" in {', '    type master;', '    file "localhost.zone";', '};'])
        return '\n'.join(lines) + '\n'

    # Fallback genérico RedHat
    return (
        'options {\n'
        f'    directory "{directory}";\n'
        f'    listen-on port {port} {{ 127.0.0.1; }};\n'
        '    listen-on-v6 { none; };\n'
        '    allow-query { localhost; 127.0.0.1; };\n'
        '    allow-recursion { localhost; 127.0.0.1; };\n'
        '    allow-query-cache { localhost; 127.0.0.1; };\n'
        '    recursion yes;\n'
        '    forward only;\n'
        f'    forwarders {{ {fwd_entries} }};\n'
        '    dnssec-validation auto;\n'
        '    max-cache-size 64m;\n'
        '    minimal-responses yes;\n'
        '};\n'
    )


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


def check_bind_runtime(root, main, service, run, port=5353):
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
    listeners = run(['ss', '-H', '-lntup', '( sport = :' + str(port) + ' )'])
    for line in listeners.splitlines():
        if not line.strip() or re.search(r'"named(?:-sdb)?"', line):
            continue
        fields = line.split()
        if len(fields) < 5:
            raise OperationError('Nao foi possivel identificar o endereco local do listener '+str(port)+': ' + line)
        address = fields[4].rsplit(':', 1)[0].strip('[]').split('%', 1)[0]
        if address not in ['*', '0.0.0.0', '::', '127.0.0.1']:
            try:
                parsed = ipaddress.ip_address(address)
                if parsed != ipaddress.ip_address('::ffff:127.0.0.1'):
                    continue
            except ValueError:
                raise OperationError('Endereco do listener '+str(port)+' nao reconhecido: ' + line)
        raise OperationError('Endereco local 127.0.0.1:'+str(port)+' ou wildcard ocupado por outro processo; nenhum servico foi parado: ' + line)


def port_labels(output, protocol, port=5353):
    labels = []
    for line in output.splitlines():
        match = re.match(r'^(\w+_port_t)\s+(tcp|udp)\s+(.+)$', line.strip())
        if not match or match[2] != protocol:
            continue
        for item in match[3].split(','):
            item = item.strip()
            if item == str(port):
                labels.append(match[1])
    return labels


def choose_bind_port(root, run):
    """Require canonical local BIND port 5353 on new installations."""
    return 5353


def prepare_bind_selinux(root, run, undo, port=5353):
    if not (root / 'sys/fs/selinux/enforce').exists():
        return []
    steps = []
    # 1. Authorize named_t to bind to mdns_port_t (udp/tcp 5353) via SELinux CIL policy module
    # This avoids any conflict with system-defined mdns_port_t in base policy on Fedora/RHEL.
    if shutil.which('semodule'):
        cil_content = (
            '; Astral AD & Hybrid DNS - Allow BIND to bind to port 5353\n'
            '(allow named_t mdns_port_t (udp_socket (name_bind)))\n'
            '(allow named_t mdns_port_t (tcp_socket (name_bind)))\n'
        )
        cil_dir = root / 'var/lib/astral-ad-dns/selinux'
        cil_dir.mkdir(parents=True, exist_ok=True)
        cil_file = cil_dir / 'astral_named_5353.cil'
        atomic_write(cil_file, cil_content, 0o644)
        try:
            run(['semodule', '-i', str(cil_file)])
            steps.append('SELinux: modulo CIL astral_named_5353 instalado com sucesso para porta 5353.')
            undo.append(['semodule', '-r', 'astral_named_5353'])
        except Exception as cil_err:
            steps.append(f'[AVISO] SELinux: semodule CIL aviso: {cil_err}')

    # 2. Also register port via semanage if available (non-fatal fallback)
    if shutil.which('semanage'):
        labels = optional(run, ['semanage', 'port', '-l'])
        local = optional(run, ['semanage', 'port', '-l', '-C'])
        for protocol in ['tcp', 'udp']:
            previous = port_labels(labels, protocol, port)
            if 'dns_port_t' in previous:
                continue
            local_previous = port_labels(local, protocol, port)
            for action in (['-m', '-a'] if previous else ['-a', '-m']):
                try:
                    run(['semanage', 'port', action, '-t', 'dns_port_t', '-p', protocol, str(port)])
                    undo.append(['semanage', 'port', '-m', '-t', local_previous[0], '-p', protocol, str(port)]
                                if local_previous else ['semanage', 'port', '-d', '-p', protocol, str(port)])
                    steps.append(f'SELinux: {protocol}/{port} autorizado como dns_port_t para o BIND.')
                    break
                except Exception:
                    continue

    if root == Path('/'):
        for boolean in ['named_bind_multicast_ports', 'named_tcp_bind_http_port']:
            try:
                run(['setsebool', '-P', boolean, '1'])
                steps.append(f'SELinux: boolean {boolean} ativado.')
            except Exception:
                pass
    return steps


def is_apparmor_enabled(root=Path('/')):
    param = root / 'sys/module/apparmor/parameters/enabled'
    if param.exists():
        try:
            return param.read_text().strip().upper() in ('Y', '1', 'TRUE')
        except OSError:
            pass
    return False


def prepare_bind_apparmor(root, run, undo):
    if not is_apparmor_enabled(root):
        return []
    profile = root / 'etc/apparmor.d/usr.sbin.named'
    if not profile.exists():
        return []
    local_dir = root / 'etc/apparmor.d/local'
    local_dir.mkdir(parents=True, exist_ok=True)
    local_profile = local_dir / 'usr.sbin.named'

    rules = [
        '/etc/bind/** lrw,',
        '/var/cache/bind/** lrw,',
        '/var/lib/samba/bind-dns/** rwk,',
    ]
    existing = local_profile.read_text() if local_profile.exists() else None
    existing_text = existing or ''
    needed = [r for r in rules if r not in existing_text]
    steps = []
    if needed:
        new_text = (existing_text.rstrip() + '\n' + '\n'.join(needed) + '\n').lstrip()
        atomic_write(local_profile, new_text, 0o644)
        undo.append(('file', local_profile, existing))
        steps.append('AppArmor: regras para BIND adicionadas em /etc/apparmor.d/local/usr.sbin.named.')
    parser = shutil.which('apparmor_parser')
    if parser:
        try:
            run([parser, '-r', str(profile)])
            steps.append('AppArmor: perfil usr.sbin.named recarregado.')
        except OperationError as err:
            steps.append(f'AppArmor: aviso ao recarregar perfil usr.sbin.named: {err}')
    return steps


def configure_bind_defaults(root):
    """Tranquil IT Debian: Disable IPv6 bind and resolvconf integration in /etc/default/named."""
    for default_path in [root / 'etc/default/named', root / 'etc/default/bind9']:
        if default_path.is_symlink():
            continue
        text = default_path.read_text() if default_path.exists() else ''
        text = re.sub(r'(?im)^\s*RESOLVCONF\s*=.*$', '', text)
        text = re.sub(r'(?im)^\s*OPTIONS\s*=.*$', '', text)
        text = text.rstrip() + '\n# Astral AD DNS\nRESOLVCONF=no\nOPTIONS="-4 -u bind"\n'
        atomic_write(default_path, text.lstrip(), 0o644)


def configure_distro_bind_environment(root, profile, port=5353, run=checked_run):
    """Configures distro-specific environment files, service drop-ins, and directories for BIND."""
    if profile.family == 'debian':
        configure_bind_defaults(root)
        cache_dir = root / profile.bind_work_dir.lstrip('/')
        cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            run(['chown', '-R', f'{profile.bind_user}:{profile.bind_group}', str(cache_dir)])
        except (OperationError, FileNotFoundError, PermissionError):
            pass
    elif profile.family == 'redhat':
        sysconfig = root / 'etc/sysconfig/named'
        if not sysconfig.is_symlink():
            sysconfig.parent.mkdir(parents=True, exist_ok=True)
            text = sysconfig.read_text() if sysconfig.exists() else ''
            if 'OPTIONS=' not in text:
                text = text.rstrip() + '\n# Astral AD DNS\nOPTIONS="-4"\n'
                atomic_write(sysconfig, text.lstrip(), 0o644)
        for sub in ['data', 'dynamic']:
            d = root / f'var/named/{sub}'
            d.mkdir(parents=True, exist_ok=True)
            try:
                run(['chown', f'{profile.bind_user}:{profile.bind_group}', str(d)])
                run(['chmod', '770', str(d)])
            except (OperationError, FileNotFoundError, PermissionError):
                pass
    elif profile.family == 'arch':
        conf_d = root / 'etc/conf.d/named'
        if not conf_d.is_symlink():
            conf_d.parent.mkdir(parents=True, exist_ok=True)
            text = conf_d.read_text() if conf_d.exists() else ''
            if 'NAMED_ARGS=' not in text:
                text = text.rstrip() + '\n# Astral AD DNS\nNAMED_ARGS="-4 -u named"\n'
                atomic_write(conf_d, text.lstrip(), 0o644)
        run_named = root / 'run/named'
        run_named.mkdir(parents=True, exist_ok=True)
        try:
            run(['chown', f'{profile.bind_user}:{profile.bind_group}', str(run_named)])
        except (OperationError, FileNotFoundError, PermissionError):
            pass
    elif profile.family == 'suse':
        sysconfig = root / 'etc/sysconfig/named'
        if not sysconfig.is_symlink():
            sysconfig.parent.mkdir(parents=True, exist_ok=True)
            text = sysconfig.read_text() if sysconfig.exists() else ''
            if 'NAMED_ARGS=' not in text:
                text = text.rstrip() + '\n# Astral AD DNS\nNAMED_ARGS="-4"\n'
                atomic_write(sysconfig, text.lstrip(), 0o644)
        override_dir = root / 'etc/systemd/system/named.service.d'
        override_dir.mkdir(parents=True, exist_ok=True)
        dropin = (
            '[Service]\n'
            'ReadWritePaths=/var/lib/named /run/named /var/log/named /var/lib/samba/bind-dns\n'
        )
        atomic_write(override_dir / 'override.conf', dropin, 0o644)
        try:
            run(['systemctl', 'daemon-reload'])
        except (OperationError, FileNotFoundError, PermissionError):
            pass


def wait_bind_ready(run, service, attempts=15, port=5353):
    """Wait for the local recursive listener, separately from AD discovery on :53."""
    last_error = 'listener ainda indisponivel'
    for attempt in range(attempts):
        try:
            status = optional(run, ['systemctl', 'is-active', service]).strip()
            if status == 'active':
                for qname in ['localhost', '.']:
                    try:
                        reply = run(['dig', '@127.0.0.1', '-p', str(port), qname, 'SOA', '+tries=1', '+time=1'])
                        if any(s in reply for s in ['status: NOERROR', 'status: NXDOMAIN', 'status: REFUSED', 'status: SERVFAIL']):
                            return
                    except Exception as probe_err:
                        last_error = str(probe_err)
        except Exception as error:
            last_error = str(error)
        time.sleep(0.5)
    details = []
    for command in [
        ['systemctl', 'show', service, '-p', 'ActiveState', '-p', 'SubState', '-p', 'ExecStart'],
        ['journalctl', '-u', service, '-n', '80', '--no-pager'],
        ['ss', '-H', '-lntup', '( sport = :' + str(port) + ' )'],
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
    raise OperationError('BIND recursivo LOCAL nao respondeu em TCP/UDP 127.0.0.1:'+str(port)+'; '
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
    port = choose_bind_port(root, run)
    if not request.get('dry_run'):
        samba_config = root / 'etc/samba/smb.conf'
        if samba_config.is_file():
            smb_forwarders = re.findall(r'(?im)^\s*dns forwarder\s*=\s*(\S+)', samba_config.read_text())
            old_value = smb_forwarders[-1] if smb_forwarders else ''
            if old_value.startswith('127.0.0.1:') and old_value != '127.0.0.1:5353':
                raise OperationError('O Samba ja encaminha para '+old_value+
                                     '. Migracao para 5353 exige manutencao '
                                     'explicita e validacao SELinux/DNS; '
                                     'o provisionamento nao mudara a porta.')
    request['bind_port'] = port
    profile = detect_distro_profile(root)
    original_text = original.decode() if original else ''
    
    # Gera configuração nativa específica da distribuição detectada
    candidate = generate_distro_bind_config(profile.family, forwarders, directory, port, root)
    if original_text and profile.family != 'debian':
        custom_zones = extract_user_zones(original_text)
        if custom_zones:
            candidate = candidate.rstrip() + '\n\n// Zonas personalizadas existentes preservadas\n' + custom_zones + '\n'

    if request.get('dry_run'):
        return ['Plano BIND: TCP/UDP 127.0.0.1:'+str(port)+', ACL localhost, forward only, DNSSEC e cache 64 MiB.',
                'Distro detectada: ' + profile.family,
                'Forwarders validados: ' + ', '.join(forwarders),
                'Nenhuma configuração ou serviço foi alterado.']
    config.parent.mkdir(parents=True, exist_ok=True)
    staged = config.with_name('.astral-named-' + uuid.uuid4().hex)
    backup = config.with_name(config.name + '.pre-astral-' + uuid.uuid4().hex)
    was_active = False
    installed = False
    selinux_undo = []
    selinux_steps = []
    apparmor_undo = []
    apparmor_steps = []
    try:
        configure_distro_bind_environment(root, profile, port, run)
        if root == Path('/'):
            try:
                run(['systemctl', 'mask', '--now', 'avahi-daemon.service', 'avahi-daemon.socket'])
                run(['systemctl', 'stop', 'avahi-daemon.service', 'avahi-daemon.socket'])
            except (OperationError, FileNotFoundError):
                pass
        if profile.family == 'debian' and root == Path('/'):
            rndc_key = root / 'etc/bind/rndc.key'
            if rndc_key.is_file():
                try:
                    run(['chown', f'root:{profile.bind_group}', str(rndc_key)])
                    run(['chmod', '640', str(rndc_key)])
                except (OperationError, FileNotFoundError):
                    pass
        check_bind_runtime(root, main, service, run, port)
        atomic_write(staged, candidate, 0o640)
        run(['chown', f'root:{profile.bind_group}', str(staged)])
        run(['named-checkconf', str(staged)])
        try:
            was_active = run(['systemctl', 'is-active', service]).strip() == 'active'
        except OperationError:
            pass
        if original is not None:
            shutil.copy2(config, backup)
            if hasattr(os, 'chown'):
                os.chown(backup, original_stat.st_uid, original_stat.st_gid)
        os.replace(staged, config)
        installed = True
        run(['named-checkconf', str(main)])
        if shutil.which('restorecon') and root == Path('/'):
            run(['restorecon', str(config)])
        if profile.security_system == 'selinux':
            selinux_steps = prepare_bind_selinux(root, run, selinux_undo, port)
        elif profile.security_system == 'apparmor':
            apparmor_steps = prepare_bind_apparmor(root, run, apparmor_undo)
        run(['systemctl', 'restart', service])
        wait_bind_ready(run, service, port=port)
        run(['systemctl', 'enable', service])
        return package_steps + (['Porta alternativa '+str(port)+' selecionada para preservar SELinux udp/5353.'] if port != 5353 else []) + selinux_steps + apparmor_steps + [f'BIND {service} validado e ativo em 127.0.0.1:{port}.',
                'Forwarders: ' + ', '.join(forwarders), f'Configuração anterior: {backup}' if original is not None else 'Nova configuração criada.']
    except Exception as error:
        rollback_errors = []
        for undo_item in reversed(apparmor_undo):
            try:
                if undo_item[0] == 'file':
                    if undo_item[2] is None:
                        undo_item[1].unlink(missing_ok=True)
                    else:
                        atomic_write(undo_item[1], undo_item[2], 0o644)
            except Exception as failure:
                rollback_errors.append('AppArmor: ' + str(failure))
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
        for service in ['samba-ad-dc', 'samba-dc', 'samba']:
            try:
                if run(['systemctl', 'is-active', service]).strip() == 'active':
                    active_services.append(service)
            except OperationError:
                pass
        service = active_services[0] if active_services else request.get('samba_service', 'samba-ad-dc' if (root / 'etc/debian_version').exists() else 'samba')
        if not active_services and 'samba_service' not in request:
            for candidate in ['samba-ad-dc', 'samba-dc', 'samba']:
                try:
                    if run(['systemctl', 'show', '--property=LoadState', '--value', candidate]).strip() == 'loaded':
                        service = candidate
                        break
                except OperationError:
                    pass
        if service not in ['samba-ad-dc', 'samba-dc', 'samba']:
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
DEMOTE_PROGRAM = r'''import json, os, pathlib, re, shutil, socket, subprocess, sys, time, uuid
request = json.load(sys.stdin)
name = request["target_name"].upper()
partner = request["primary_hostname"]
admin = request["admin_username"]
backup_dir = None
steps = []

def run(args, timeout=90):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-2000:])
    return result.stdout

def credential_run(args, timeout=300):
    # Samba's PASSWD_FD avoids command-line credentials and temporary files.
    password = request.get("admin_password", "")
    if not password:
        raise RuntimeError("Senha administrativa ausente.")
    rfd, wfd = os.pipe()
    try:
        os.write(wfd, password.encode("utf-8") + bytes((10,)))
        os.close(wfd)
        wfd = -1
        env = os.environ.copy()
        env.pop("PASSWD", None)
        env.pop("PASSWD_FILE", None)
        env["PASSWD_FD"] = str(rfd)
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                                env=env, pass_fds=(rfd,))
        if result.returncode:
            message = (result.stderr or result.stdout)[-2500:].replace(password, "[REDACTED]")
            raise RuntimeError(message)
        return result.stdout
    finally:
        os.close(rfd)
        if wfd != -1:
            os.close(wfd)

def remote_account():
    # Force the primary's LDAP view, not this host's obsolete sam.ldb.
    output = credential_run(["samba-tool", "computer", "show", name,
                             "-H", "ldap://" + partner, "-U" + admin])
    values = {}
    for line in output.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key.lower()] = value.strip()
    flags = int(values.get("useraccountcontrol", "-1"))
    group = values.get("primarygroupid", "")
    if flags & 0x2000 or group in ("516", "521"):
        return "dc"
    if flags & 0x1000 and group == "515":
        return "member"
    raise RuntimeError("Estado da conta no DC primário não é DC nem membro confirmado; abortado.")

def check_primary_reachable():
    endpoints = socket.getaddrinfo(partner, 389, type=socket.SOCK_STREAM)
    if not endpoints:
        raise RuntimeError("Nome do DC primário não resolve.")
    reachable = []
    for family, kind, protocol, _, addr in endpoints:
        try:
            with socket.socket(family, kind, protocol) as sock:
                sock.settimeout(4)
                sock.connect(addr)
            reachable.append(addr[0])
        except OSError:
            continue
    if not reachable:
        raise RuntimeError("LDAP TCP 389 do DC primário inacessível.")
    return reachable[0]

def local_dns_addresses():
    addresses = {"127.0.0.1", "127.0.0.53", "::1"}
    result = subprocess.run(["ip", "-o", "-4", "addr", "show"], text=True,
                            capture_output=True, timeout=15)
    if result.returncode == 0:
        for item in re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", result.stdout):
            addresses.add(item)
    return addresses

def validate_member_runtime():
    for cmd in ("net", "smbd", "winbindd", "testparm"):
        if shutil.which(cmd) is None:
            raise RuntimeError("Componente de membro ausente: " + cmd)
    for candidates in (("smb", "smbd"), ("winbind", "winbindd")):
        if not any(service_exists(unit) for unit in candidates):
            raise RuntimeError("Serviço de membro ausente: " + "/".join(candidates))
    resolver = pathlib.Path("/etc/resolv.conf")
    if not resolver.is_file():
        raise RuntimeError("resolv.conf inexistente.")
    nameservers = re.findall(r"(?m)^\s*nameserver\s+(\S+)", resolver.read_text())
    if resolver.is_symlink() and nameservers and all(
            address in local_dns_addresses() for address in nameservers):
        raise RuntimeError("DNS do host usa apenas loopback por symlink; ajuste o resolvedor antes de converter o DC.")

def copy_private_without_special(private, destination):
    # Samba runtime sockets are not files and cannot be backed up. All
    # regular databases must be copied, or copytree fails closed.
    import stat
    def skip_special(directory, names):
        ignored = []
        for entry in names:
            path = pathlib.Path(directory) / entry
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                ignored.append(entry)
                continue
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                ignored.append(entry)
        return ignored
    shutil.copytree(private, destination, symlinks=True, ignore=skip_special)
    if (private / "sam.ldb").is_file() and not (destination / "sam.ldb").is_file():
        raise RuntimeError("Backup da base AD sam.ldb incompleto; conversão bloqueada.")

def create_backup():
    root = pathlib.Path("/var/backups/astral-ad-dns/demote")
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    dest = root / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    dest.mkdir(mode=0o700)
    source_conf = pathlib.Path("/etc/samba/smb.conf")
    if not source_conf.is_file() or source_conf.is_symlink():
        raise RuntimeError("smb.conf ausente ou link simbólico; backup seguro não disponível.")
    shutil.copy2(source_conf, dest / "smb.conf")
    private = pathlib.Path("/var/lib/samba/private")
    if private.exists():
        copy_private_without_special(private, dest / "private")
    resolver = pathlib.Path("/etc/resolv.conf")
    if resolver.is_file():
        shutil.copy2(resolver, dest / "resolv.conf")
    return dest

def prepare_resolver(primary_ip):
    resolver = pathlib.Path("/etc/resolv.conf")
    if not resolver.is_file():
        raise RuntimeError("resolv.conf inexistente.")
    contents = resolver.read_text()
    nameservers = re.findall(r"(?m)^\s*nameserver\s+(\S+)", contents)
    if nameservers and all(address in ("127.0.0.1", "127.0.0.53", "::1") for address in nameservers):
        if resolver.is_symlink():
            raise RuntimeError("resolv.conf gerenciado por symlink ainda aponta só para loopback; não será sobrescrito.")
        search = "search " + request["realm"].lower() + "\n"
        resolver.write_text(search + "nameserver " + primary_ip + "\n")
        steps.append("DNS local redirecionado ao DC primário após backup.")

def service_exists(unit):
    return subprocess.run(["systemctl", "cat", unit], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0

def stop_old_dc():
    for unit in ("samba-ad-dc", "samba-dc", "samba"):
        if service_exists(unit):
            run(["systemctl", "disable", "--now", unit], timeout=60)
    steps.append("Daemon AD DC parado e desabilitado.")

def write_member_config(realm, workgroup, netbios):
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{0,14}", netbios):
        raise RuntimeError("NetBIOS local inválido.")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9.-]+", realm):
        raise RuntimeError("Realm local inválido.")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{0,14}", workgroup):
        raise RuntimeError("Workgroup local inválido.")
    text = ("[global]\n"
            "    netbios name = " + netbios + "\n"
            "    workgroup = " + workgroup + "\n"
            "    realm = " + realm + "\n"
            "    security = ADS\n"
            "    server role = member server\n"
            "    kerberos method = secrets and keytab\n"
            "    idmap config * : backend = tdb\n"
            "    idmap config * : range = 3000-7999\n"
            "    idmap config " + workgroup + " : backend = rid\n"
            "    idmap config " + workgroup + " : range = 10000-999999\n"
            "    winbind use default domain = yes\n")
    target = pathlib.Path("/etc/samba/smb.conf")
    temp = target.with_name("smb.conf.astral-demote-" + uuid.uuid4().hex)
    temp.write_text(text)
    os.chmod(temp, 0o600)
    os.replace(temp, target)
    run(["testparm", "-s", str(target)])
    role = run(["testparm", "-s", "--parameter-name=server role"]).strip().lower()
    if "member server" not in role:
        raise RuntimeError("Configuração local não assumiu papel member server.")
    steps.append("smb.conf convertido para Samba AD member server, configuração anterior preservada.")

def start_member_services():
    for candidates in (("smb", "smbd"), ("winbind", "winbindd")):
        unit = next((u for u in candidates if service_exists(u)), None)
        if not unit:
            raise RuntimeError("Unidade de serviço membro não encontrada: " + "/".join(candidates))
        run(["systemctl", "enable", "--now", unit], timeout=60)
    steps.append("SMB e Winbind ativados sem reativar o daemon AD DC.")

try:
    netbios = run(["testparm", "-s", "--parameter-name=netbios name"]).strip().upper()
    if netbios != name:
        raise RuntimeError("Identidade local não corresponde ao DC selecionado.")
    realm = run(["testparm", "-s", "--parameter-name=realm"]).strip().upper()
    workgroup = run(["testparm", "-s", "--parameter-name=workgroup"]).strip().upper()
    request["realm"] = realm
    primary_ip = check_primary_reachable()
    state = remote_account()
    # Fail BEFORE committing changes in the AD if this host cannot act as
    # a member, and preserve the complete pre-demotion private database.
    validate_member_runtime()
    backup_dir = create_backup()
    steps.append("Backup protegido em " + str(backup_dir))
    if state == "dc":
        # A live DC may be demoted only when no FSMO role remains here.
        fsmo = run(["samba-tool", "fsmo", "show"]).upper()
        if ("CN=NTDS SETTINGS,CN=" + name + ",") in fsmo:
            raise RuntimeError("DC ainda possui funções FSMO; despromoção bloqueada.")
        try:
            credential_run(["samba-tool", "domain", "demote", "-U" + admin])
        except RuntimeError:
            # Samba may commit on the partner then fail its local finalization.
            if remote_account() != "member":
                raise
            steps.append("Despromoção remota já concluída; recuperando finalização local.")
        if remote_account() != "member":
            raise RuntimeError("O DC primário não confirmou a conta como membro após a despromoção.")
        steps.append("Conta de domínio confirmada como membro pelo DC primário.")
    else:
        steps.append("O DC primário já reconhece esta máquina como membro; despromoção não repetida.")
    # Never convert an unverified DC. After remote commit, preserve its old
    # database and finish as a member without starting the stale DC daemon.
    stop_old_dc()
    prepare_resolver(primary_ip)
    write_member_config(realm, workgroup, netbios)
    credential_run(["net", "ads", "join", "-S", partner, "-U" + admin])
    run(["net", "ads", "testjoin"])
    start_member_services()
    # Keep the trusted DC used for LDAP reads in a separate Astral metadata
    # file; the member Samba configuration itself remains standard.
    metadata = pathlib.Path("/etc/astral-ad-dns/member-server.json")
    metadata.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = metadata.with_name(metadata.name + ".tmp-" + uuid.uuid4().hex)
    temp.write_text(json.dumps({"primary_hostname": partner, "netbios": netbios, "realm": realm}))
    os.chmod(temp, 0o600)
    os.replace(temp, metadata)
    if remote_account() != "member":
        raise RuntimeError("Estado da conta deixou de ser membro durante validação final.")
    if any(service_exists(u) and subprocess.run(["systemctl", "is-active", "--quiet", u]).returncode == 0 for u in ("samba-ad-dc", "samba-dc", "samba")):
        raise RuntimeError("O serviço AD DC continuou ativo após a conversão.")
    steps.append("Validação final: net ads testjoin OK e conta de membro confirmada no DC primário.")
    print(json.dumps({"success": True, "steps": steps}))
except Exception as error:
    message = str(error).replace(request.get("admin_password", ""), "[REDACTED]")
    if backup_dir:
        message += " | Backup preservado: " + str(backup_dir) + " | Não reative o AD DC automaticamente."
    print(json.dumps({"success": False, "error": message, "steps": steps}))
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
    return response.get('steps', ['Despromoção concluída e servidor membro validado.'])


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
    parser.add_argument('operation', choices=['restore', 'bind', 'demote', 'transition', 'forensic', 'provision', 'pki'])
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
                    if fcntl:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    data = execute(request)
            else:
                data = execute(request)
            print(json.dumps({'success': True, 'data': data}, ensure_ascii=False))
            return
        lock_path = Path('/run/lock/astral-ad-operations.lock')
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open('a') as lock:
            if fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == 'pki':
                from pki_management import execute
                data = execute(request)
                print(json.dumps({'success': True, 'data': data}, ensure_ascii=False))
                return
            if args.operation == 'provision':
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
