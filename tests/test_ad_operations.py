import ast
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import os
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('operations', Path(__file__).resolve().parents[1] / 'samba-ad-dc/ad_operations.py')
operations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operations)


def make_backup(root, filename='backup.tar.bz2', unsafe=False):
    directory = root / 'var/backups/samba'
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / filename
    with tarfile.open(archive, 'w:bz2') as tar:
        for name, data in {'./backup.txt': b'Backup contains domain secrets: True', 'etc/smb.conf': b'[global]',
                           'sysvol.tar.gz': b'fake sysvol handled by Samba', 'private/sam.ldb': b'old database'}.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        if unsafe:
            member = tarfile.TarInfo('../escape')
            tar.addfile(member)
    return archive


class FakeRunner:
    def __init__(self, root, fail=None):
        self.root = root
        self.fail = fail
        self.calls = []
        self.active = {'samba': True, 'named': True}

    def __call__(self, args):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise operations.OperationError('injected failure')
        if args[:4] == ['samba-tool', 'domain', 'backup', 'restore']:
            stage = Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--targetdir=')))
            (stage / 'etc').mkdir(parents=True)
            (stage / 'private').mkdir()
            (stage / 'sysvol').mkdir()
            (stage / 'private/sam.ldb').write_text('recovered database')
            (stage / 'private/krb5.conf').write_text('[libdefaults]\n default_realm = EXAMPLE.TEST\n')
            (stage / 'sysvol/policy').write_text('recovered policy')
            (stage / 'etc/smb.conf').write_text(f'[global]\n realm = EXAMPLE.TEST\n private dir = {stage}/private\n server services = -dns\n[sysvol]\n path = {stage}/sysvol\n')
        if args[0] == 'systemctl':
            if args[1] == 'is-active':
                if not self.active.get(args[2], False):
                    raise operations.OperationError('inactive')
                return 'active\n'
            if args[1] in ['start', 'restart']:
                self.active[args[2]] = True
            if args[1] == 'stop':
                self.active[args[2]] = False
        if args[0] == 'dig':
            return ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
        return ''


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.request = {'filename': 'backup.tar.bz2', 'new_server_name': 'RECOVERY', 'host_ip': '192.0.2.10',
                        'replace_existing': True, 'isolated_recovery_confirmed': True}
        make_backup(self.root)

    def existing(self):
        live = self.root / 'var/lib/samba/private'
        live.mkdir(parents=True)
        (live / 'sam.ldb').write_text('original database')
        config = self.root / 'etc/samba/smb.conf'
        config.parent.mkdir(parents=True)
        config.write_text('original configuration')
        (self.root / 'etc/krb5.conf').write_text('original kerberos')
        return config

    def test_recovery_does_not_mix_databases_and_rewrites_all_paths(self):
        self.existing()
        live = self.root / 'var/lib/samba'
        (live / 'stale.ldb').write_text('stale')
        runner = FakeRunner(self.root)
        operations.restore_domain(self.request, self.root, runner)
        self.assertFalse((live / 'stale.ldb').exists())
        self.assertEqual((live / 'private/sam.ldb').read_text(), 'recovered database')
        config = (self.root / 'etc/samba/smb.conf').read_text()
        self.assertIn(str(live / 'private'), config)
        self.assertNotIn('samba.restore-', config)
        self.assertNotIn('-dns', config)
        self.assertIn('127.0.0.1:5353', config)
        previous = list((self.root / 'var/lib').glob('samba.pre-restore-*'))
        self.assertEqual((previous[0] / 'private/sam.ldb').read_text(), 'original database')

    def test_post_activation_failure_rolls_back_database_config_and_service(self):
        config = self.existing()
        runner = FakeRunner(self.root, lambda args: args[:4] == ['samba-tool', 'domain', 'level', 'show'])
        with self.assertRaises(operations.OperationError):
            operations.restore_domain(self.request, self.root, runner)
        self.assertEqual((self.root / 'var/lib/samba/private/sam.ldb').read_text(), 'original database')
        self.assertEqual(config.read_text(), 'original configuration')
        self.assertEqual((self.root / 'etc/krb5.conf').read_text(), 'original kerberos')
        self.assertTrue(runner.active['samba'])

    def test_invalid_archive_never_stops_services(self):
        make_backup(self.root, unsafe=True)
        runner = FakeRunner(self.root)
        with self.assertRaises(operations.OperationError):
            operations.restore_domain(self.request, self.root, runner)
        self.assertEqual(runner.calls, [])

    def test_restore_failure_never_extracts_into_live_database(self):
        self.existing()
        runner = FakeRunner(self.root, lambda args: args[:4] == ['samba-tool', 'domain', 'backup', 'restore'])
        with self.assertRaises(operations.OperationError):
            operations.restore_domain(self.request, self.root, runner)
        self.assertEqual((self.root / 'var/lib/samba/private/sam.ldb').read_text(), 'original database')
        self.assertFalse(any(args[:2] == ['systemctl', 'stop'] for args in runner.calls))
        self.assertFalse(any(args[0] == 'tar' for args in runner.calls))

    def test_recovery_requires_both_replacement_and_isolation_consent(self):
        self.existing()
        for key in ['replace_existing', 'isolated_recovery_confirmed']:
            request = dict(self.request, **{key: False})
            runner = FakeRunner(self.root)
            with self.assertRaises(operations.OperationError):
                operations.restore_domain(request, self.root, runner)
            self.assertEqual(runner.calls, [])

    def test_simulation_does_not_change_files_or_services(self):
        self.existing()
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        runner = FakeRunner(self.root)
        operations.restore_domain(dict(self.request, dry_run=True), self.root, runner)
        operations.configure_bind({'forwarders': ['9.9.9.9'], 'dry_run': True}, self.root, runner)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertEqual(runner.calls, [])

    def test_bind_reload_failure_restores_previous_file(self):
        config = self.root / 'etc/named.conf'
        config.parent.mkdir()
        original = 'options { recursion no; };\nzone "example.test" { type primary; file "zone"; };\n'
        config.write_text(original)
        runner = FakeRunner(self.root, lambda args: args[:2] == ['systemctl', 'restart'])
        with self.assertRaises(operations.OperationError):
            operations.configure_bind({'forwarders': ['9.9.9.9']}, self.root, runner)
        self.assertEqual(config.read_text(), original)

    def test_bind_preserves_zones_and_enforces_localhost_acl(self):
        config = self.root / 'etc/named.conf'
        config.parent.mkdir()
        config.write_text('options { forwarders { 8.8.8.8; }; };\nzone "example.test" { type primary; file "zone"; };\n')
        runner = FakeRunner(self.root)
        operations.configure_bind({'forwarders': ['9.9.9.9', '2606:4700:4700::1111', '9.9.9.9']}, self.root, runner)
        content = config.read_text()
        self.assertIn('zone "example.test"', content)
        self.assertEqual(content.count('9.9.9.9;'), 1)
        self.assertIn('allow-recursion { localhost; }', content)
        self.assertIn('listen-on port 5353 { 127.0.0.1; }', content)
        self.assertEqual(len([args for args in runner.calls if args[0] == 'dig']), 2)

    def test_bind_invalid_upstream_or_dlz_is_rejected_before_mutation(self):
        for forwarders in [[], ['127.0.0.1'], ['::1'], ['any'], ['8.8.8.8; bad'], ['0.0.0.0']]:
            runner = FakeRunner(self.root)
            with self.assertRaises(operations.OperationError):
                operations.configure_bind({'forwarders': forwarders}, self.root, runner)
            self.assertEqual(runner.calls, [])
        with self.assertRaises(operations.OperationError):
            operations.replace_options('dlz "AD DNS" { database "dlopen x"; };', 'options {};')

    def test_servfail_rolls_back_even_if_dig_exits_zero(self):
        config = self.root / 'etc/named.conf'
        config.parent.mkdir()
        config.write_text('options { recursion no; };')
        runner = FakeRunner(self.root)
        def failing_dns(args):
            return 'status: SERVFAIL' if args[0] == 'dig' else runner(args)
        with patch.object(operations.time, 'sleep'), self.assertRaises(operations.OperationError):
            operations.configure_bind({'forwarders': ['9.9.9.9']}, self.root, failing_dns)
        self.assertEqual(config.read_text(), 'options { recursion no; };')

    def test_bind_waits_for_listener_after_restart(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[0] == 'dig' and len(calls) == 1:
                raise operations.OperationError('connection refused')
            return 'status: NOERROR'
        with patch.object(operations.time, 'sleep'):
            operations.wait_bind_ready(run, 'named')
        self.assertEqual(len(calls), 3)
        self.assertIn('+tcp', calls[-1])

    def test_bind_failure_identifies_local_service_and_collects_diagnostics(self):
        def run(args):
            if args[0] == 'dig':
                raise operations.OperationError('connection refused')
            return 'named listener unavailable'
        with patch.object(operations.time, 'sleep'):
            with self.assertRaisesRegex(operations.OperationError, 'LOCAL.*5353.*named listener unavailable'):
                operations.wait_bind_ready(run, 'named', attempts=2)

    def selinux_fixture(self):
        enforce = self.root / 'sys/fs/selinux/enforce'
        enforce.parent.mkdir(parents=True)
        enforce.write_text('1')
        config = self.root / 'etc/named.conf'
        config.parent.mkdir(exist_ok=True)
        config.write_text('options { recursion no; };')
        return config

    def test_selinux_port_labels_cover_tcp_udp_and_have_precise_undo(self):
        self.selinux_fixture()
        calls, undo = [], []
        def run(args):
            calls.append(args)
            if args == ['semanage', 'port', '-l']:
                return 'dns_port_t tcp 53\nmdns_port_t udp 5353\n'
            return ''
        with patch.object(operations.shutil, 'which', return_value='/usr/sbin/semanage'):
            steps = operations.prepare_bind_selinux(self.root, run, undo)
        self.assertEqual(len(steps), 2)
        self.assertIn(['semanage', 'port', '-a', '-t', 'dns_port_t', '-p', 'tcp', '5353'], calls)
        self.assertIn(['semanage', 'port', '-m', '-t', 'dns_port_t', '-p', 'udp', '5353'], calls)
        self.assertEqual(undo, [['semanage', 'port', '-d', '-p', 'tcp', '5353'], ['semanage', 'port', '-d', '-p', 'udp', '5353']])

    def test_ambiguous_selinux_5353_blocks_no_port_switch(self):
        config=self.selinux_fixture()
        before=config.read_text()
        calls=[]
        def run(args):
            calls.append(args)
            if args==['semanage','port','-l']:
                return ('dns_port_t tcp 53,5353\n'
                        'mdns_port_t udp 5353\n'
                        'custom_port_t udp 5353\n')
            return ''
        with self.assertRaisesRegex(operations.OperationError,'5353'):
            operations.configure_bind({'forwarders':['9.9.9.9']},self.root,run)
        self.assertEqual(config.read_text(),before)
        self.assertFalse(any(args[0] in ('systemctl','semanage') and args[:2]!=['semanage','port'] for args in calls))
        self.assertFalse(any(args[:3]==['semanage','port','-m'] for args in calls))

    def test_existing_15353_forwarder_cannot_be_changed_implicitly(self):
        self.selinux_fixture()
        samba=self.root/'etc/samba/smb.conf'
        samba.parent.mkdir(parents=True)
        samba.write_text('[global]\n    dns forwarder = 127.0.0.1:15353\n')
        with self.assertRaisesRegex(operations.OperationError,'Migracao para 5353'):
            operations.configure_bind({'forwarders':['9.9.9.9']},self.root,
                                      lambda args: '')
        self.assertIn('127.0.0.1:15353',samba.read_text())

    def test_unambiguous_selinux_prefers_5353(self):
        self.selinux_fixture()
        def run(args):
            if args==['semanage','port','-l']:
                return 'mdns_port_t udp 5353\n'
            return ''
        self.assertEqual(operations.choose_bind_port(self.root,run),5353)

    def test_selinux_failure_undoes_previous_port_and_preserves_config(self):
        config = self.selinux_fixture()
        runner = FakeRunner(self.root)
        def run(args):
            if args == ['semanage', 'port', '-l']:
                return 'mdns_port_t udp 5353\n'
            if args[:3] == ['semanage', 'port', '-m']:
                raise operations.OperationError('policy mutation failed')
            return runner(args)
        with patch.object(operations.shutil, 'which', return_value='/usr/sbin/semanage'):
            with self.assertRaisesRegex(operations.OperationError, 'policy mutation failed'):
                operations.configure_bind({'forwarders': ['9.9.9.9']}, self.root, run)
        self.assertEqual(config.read_text(), 'options { recursion no; };')
        self.assertIn(['semanage', 'port', '-d', '-p', 'tcp', '5353'], runner.calls)
        self.assertFalse(any(args[0] == 'dig' for args in runner.calls))

    def test_preexisting_local_selinux_label_is_restored_not_deleted(self):
        self.selinux_fixture()
        undo = []
        def run(args):
            if args == ['semanage', 'port', '-l']:
                return 'dns_port_t tcp 5353\ncustom_port_t udp 5353\n'
            if args == ['semanage', 'port', '-l', '-C']:
                return 'custom_port_t udp 5353\n'
            return ''
        with patch.object(operations.shutil, 'which', return_value='/usr/sbin/semanage'):
            operations.prepare_bind_selinux(self.root, run, undo)
        self.assertEqual(undo, [['semanage', 'port', '-m', '-t', 'custom_port_t', '-p', 'udp', '5353']])

    def test_foreign_5353_listener_is_preserved(self):
        config = self.root / 'etc/named.conf'
        config.parent.mkdir()
        config.write_text('options { recursion no; };')
        runner = FakeRunner(self.root)
        def run(args):
            if args[0] == 'ss':
                return 'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=1,fd=2))'
            return runner(args)
        with self.assertRaisesRegex(operations.OperationError, 'ocupad[oa] por outro processo'):
            operations.configure_bind({'forwarders': ['9.9.9.9']}, self.root, run)
        self.assertEqual(config.read_text(), 'options { recursion no; };')
        self.assertFalse(any(args[:2] in [['systemctl', 'stop'], ['systemctl', 'restart']] for args in runner.calls))

    def test_custom_namedconf_is_detected_before_modification(self):
        sysconfig = self.root / 'etc/sysconfig/named'
        sysconfig.parent.mkdir(parents=True)
        sysconfig.write_text('NAMEDCONF="/etc/custom/named.conf"\n')
        with self.assertRaisesRegex(operations.OperationError, 'NAMEDCONF aponta'):
            operations.check_bind_runtime(self.root, self.root / 'etc/named.conf', 'named', FakeRunner(self.root))

    def test_missing_diagnostic_tool_does_not_hide_bind_failure(self):
        def run(args):
            if args[0] == 'dig':
                raise operations.OperationError('connection refused')
            raise FileNotFoundError(args[0])
        with self.assertRaisesRegex(operations.OperationError, 'LOCAL.*connection refused'):
            operations.wait_bind_ready(run, 'named', attempts=1)

    def test_remote_demote_rechecks_identity_and_fsmo_on_target(self):
        # The live migration script cannot be run against the CI runner:
        # its success path deliberately disables Samba and rewrites smb.conf.
        # The isolated credential/LDAP-member tests live in
        # test_demote_standard_command.py.
        tree = ast.parse(operations.DEMOTE_PROGRAM)
        self.assertTrue(any(isinstance(node, ast.FunctionDef) and node.name == 'remote_account'
                            for node in tree.body))
        code = operations.DEMOTE_PROGRAM
        self.assertIn('if netbios != name:', code)
        self.assertIn('fsmo = run(["samba-tool", "fsmo", "show"]).upper()', code)
        self.assertIn('DC ainda possui funções FSMO', code)
        self.assertIn('if state == "dc":', code)
        self.assertIn('if remote_account() != "member":', code)
        self.assertIn('stop_old_dc()', code)
        self.assertNotIn('--password=', code)



    def test_bind_apparmor_and_debian_defaults(self):
        aa_param = self.root / 'sys/module/apparmor/parameters/enabled'
        aa_param.parent.mkdir(parents=True, exist_ok=True)
        aa_param.write_text('Y\n')

        named_profile = self.root / 'etc/apparmor.d/usr.sbin.named'
        named_profile.parent.mkdir(parents=True, exist_ok=True)
        named_profile.write_text('# profile\n')

        calls = []
        undo = []
        def run(args):
            calls.append(args)
            return ''

        with patch.object(operations.shutil, 'which', return_value='/usr/sbin/apparmor_parser'):
            steps = operations.prepare_bind_apparmor(self.root, run, undo)
        self.assertTrue(any('regras para BIND adicionadas' in s for s in steps))
        local_named = self.root / 'etc/apparmor.d/local/usr.sbin.named'
        self.assertTrue(local_named.exists())
        self.assertIn('/var/cache/bind/** lrw,', local_named.read_text())
        self.assertIn(['/usr/sbin/apparmor_parser', '-r', str(named_profile)], calls)

        operations.configure_bind_defaults(self.root)
        default_named = self.root / 'etc/default/named'
        self.assertTrue(default_named.exists())
        self.assertIn('RESOLVCONF=no', default_named.read_text())
        self.assertIn('OPTIONS="-4 -u bind"', default_named.read_text())

    def test_ensure_samba_directories_creates_all_expected_paths(self):
        target = self.root / 'target_root'
        operations.ensure_samba_directories(target)
        self.assertTrue((target / 'var/cache/samba').is_dir())
        self.assertTrue((target / 'var/lib/samba').is_dir())
        self.assertTrue((target / 'var/lib/samba/private').is_dir())
        self.assertTrue((target / 'var/log/samba').is_dir())
        self.assertTrue((target / 'run/samba').is_dir())
        self.assertTrue((target / 'etc/samba').is_dir())
        if os.name != 'nt':
            self.assertEqual((target / 'var/cache/samba').stat().st_mode & 0o777, 0o755)
            self.assertEqual((target / 'var/lib/samba/private').stat().st_mode & 0o777, 0o700)

    def test_distro_profile_attributes_and_detection(self):
        # 1. Debian
        deb_root = self.root / 'deb'
        (deb_root / 'etc').mkdir(parents=True, exist_ok=True)
        (deb_root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="13"\n')
        profile_deb = operations.detect_distro_profile(deb_root)
        self.assertEqual(profile_deb.family, 'debian')
        self.assertEqual(profile_deb.samba_unit, 'samba-ad-dc')
        self.assertNotIn('samba', profile_deb.samba_conflicts)
        self.assertEqual(profile_deb.bind_user, 'bind')
        self.assertEqual(profile_deb.bind_group, 'bind')
        self.assertEqual(profile_deb.bind_work_dir, '/var/cache/bind')
        self.assertEqual(profile_deb.bind_cache, '/var/cache/bind')
        self.assertEqual(profile_deb.chrony_user, '_chrony')
        self.assertEqual(profile_deb.security_system, 'apparmor')

        # 2. RedHat / Fedora
        rh_root = self.root / 'rh'
        (rh_root / 'etc').mkdir(parents=True, exist_ok=True)
        (rh_root / 'etc/os-release').write_text('ID=fedora\nVERSION_ID="45"\n')
        profile_rh = operations.detect_distro_profile(rh_root)
        self.assertEqual(profile_rh.family, 'redhat')
        self.assertEqual(profile_rh.samba_unit, 'samba')
        self.assertEqual(profile_rh.bind_user, 'named')
        self.assertEqual(profile_rh.bind_work_dir, '/var/named')
        self.assertEqual(profile_rh.bind_cache, '/var/named')
        self.assertEqual(profile_rh.security_system, 'selinux')

        # 3. Arch Linux
        arch_root = self.root / 'arch'
        (arch_root / 'etc').mkdir(parents=True, exist_ok=True)
        (arch_root / 'etc/os-release').write_text('ID=arch\n')
        profile_arch = operations.detect_distro_profile(arch_root)
        self.assertEqual(profile_arch.family, 'arch')
        self.assertEqual(profile_arch.samba_unit, 'samba')
        self.assertEqual(profile_arch.bind_work_dir, '/var/named')
        self.assertEqual(profile_arch.bind_cache, '/var/named')
        self.assertEqual(profile_arch.security_system, 'none')

    def test_configure_bind_debian_profile_has_no_attribute_errors(self):
        deb_root = self.root / 'deb_bind'
        (deb_root / 'etc/bind').mkdir(parents=True, exist_ok=True)
        (deb_root / 'etc/os-release').write_text('ID=debian\n')
        (deb_root / 'etc/bind/named.conf').write_text('options {};\n')
        (deb_root / 'etc/bind/named.conf.options').write_text('options {};\n')
        (deb_root / 'var/cache/bind').mkdir(parents=True, exist_ok=True)

        runner = FakeRunner(deb_root)
        def run(args):
            if args[0] == 'ss':
                return ''
            return runner(args)

        steps = operations.configure_bind({'forwarders': ['8.8.8.8']}, deb_root, run)
        self.assertTrue(any('BIND named validado e ativo' in s for s in steps))

    def test_distro_specific_bind_config_generation(self):
        # 1. Debian
        deb_root = self.root / 'test_deb'
        deb_cfg = operations.generate_distro_bind_config('debian', ['8.8.8.8'], '/var/cache/bind', 5353, deb_root)
        self.assertIn('directory "/var/cache/bind";', deb_cfg)
        self.assertIn('listen-on port 5353 { 127.0.0.1; };', deb_cfg)
        self.assertTrue((deb_root / 'etc/bind/named.conf').exists())
        self.assertIn('include "/etc/bind/named.conf.options";', (deb_root / 'etc/bind/named.conf').read_text())

        # 2. RedHat
        rh_root = self.root / 'test_rh'
        (rh_root / 'etc/named.rfc1912.zones').parent.mkdir(parents=True, exist_ok=True)
        (rh_root / 'etc/named.rfc1912.zones').write_text('// rfc1912\n')
        rh_cfg = operations.generate_distro_bind_config('redhat', ['1.1.1.1'], '/var/named', 5353, rh_root)
        self.assertIn('directory "/var/named";', rh_cfg)
        self.assertIn('logging {', rh_cfg)
        self.assertIn('zone "." IN {', rh_cfg)
        self.assertIn('file "named.ca";', rh_cfg)
        self.assertIn('include "/etc/named.rfc1912.zones";', rh_cfg)

        # 3. Arch
        arch_root = self.root / 'test_arch'
        arch_cfg = operations.generate_distro_bind_config('arch', ['9.9.9.9'], '/var/named', 5353, arch_root)
        self.assertIn('directory "/var/named";', arch_cfg)
        self.assertIn('pid-file "/run/named/named.pid";', arch_cfg)

        # 4. SUSE
        suse_root = self.root / 'test_suse'
        suse_cfg = operations.generate_distro_bind_config('suse', ['8.8.4.4'], '/var/lib/named', 5353, suse_root)
        self.assertIn('directory "/var/lib/named";', suse_cfg)
        self.assertIn('dump-file "/var/log/named_dump.db";', suse_cfg)
        self.assertIn('statistics-file "/var/log/named.stats";', suse_cfg)


if __name__ == '__main__':
    unittest.main()
