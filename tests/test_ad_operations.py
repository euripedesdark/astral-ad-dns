import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import contextlib
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
        with self.assertRaises(operations.OperationError):
            operations.configure_bind({'forwarders': ['9.9.9.9']}, self.root, failing_dns)
        self.assertEqual(config.read_text(), 'options { recursion no; };')

    def test_remote_demote_rechecks_identity_and_fsmo_on_target(self):
        request = {'target_name': 'SECONDARY', 'primary_hostname': 'primary.example.test',
                   'admin_username': 'administrator', 'admin_password': 'secret-test-only'}
        for scenario in ['success', 'wrong-host', 'has-fsmo']:
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                if args[0] == 'testparm':
                    output = 'WRONG' if scenario == 'wrong-host' else 'SECONDARY'
                elif args[:3] == ['samba-tool', 'fsmo', 'show']:
                    output = 'PdcEmulationMasterRole owner: CN=NTDS Settings,CN=' + ('SECONDARY' if scenario == 'has-fsmo' else 'PRIMARY') + ',CN=Servers'
                else:
                    output = ''
                return subprocess.CompletedProcess(args, 0, output, '')
            output = io.StringIO()
            with patch('subprocess.run', side_effect=run), patch.object(sys, 'stdin', io.StringIO(json.dumps(request))), contextlib.redirect_stdout(output):
                if scenario == 'success':
                    exec(operations.DEMOTE_PROGRAM, {})
                else:
                    with self.assertRaises(SystemExit):
                        exec(operations.DEMOTE_PROGRAM, {})
            self.assertNotIn(request['admin_password'], output.getvalue())
            mutations = [args for args in calls if args[:3] == ['samba-tool', 'domain', 'demote']]
            self.assertEqual(len(mutations), 1 if scenario == 'success' else 0)



if __name__ == '__main__':
    unittest.main()
