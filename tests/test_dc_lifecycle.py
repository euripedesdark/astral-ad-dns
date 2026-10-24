import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('lifecycle', Path(__file__).resolve().parents[1] / 'samba-ad-dc/dc_lifecycle.py')
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class FakeController:
    def __init__(self, root, readonly=False, fail=None):
        self.root = root
        self.readonly = readonly
        self.fail = fail
        self.calls = []
        self.roles = {role: 'PRIMARY' for role in lifecycle.ROLES}
        self.active = True
        self.joined = False

    def __call__(self, args):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise lifecycle.TransitionError('injected command failure')
        if args[0] == 'testparm':
            if '--parameter-name=netbios name' in args:
                return 'SECONDARY'
            if '--parameter-name=realm' in args:
                return 'EXAMPLE.TEST'
            if '--parameter-name=workgroup' in args:
                return 'EXAMPLE'
            if '--section-name=sysvol' in args:
                config = Path(args[-1])
                return str(config.parent.parent / 'sysvol') if config.parent.name == 'etc' else str(self.root / 'var/lib/samba/sysvol')
            return ''
        if args[:3] == ['samba-tool', 'fsmo', 'show']:
            return '\n'.join(lifecycle.ROLES[role] + ' owner: CN=NTDS Settings,CN=' + name + ',CN=Servers' for role, name in self.roles.items())
        if args[:3] == ['samba-tool', 'fsmo', 'transfer']:
            self.roles[next(arg.split('=', 1)[1] for arg in args if arg.startswith('--role='))] = 'SECONDARY'
        if args[:3] == ['samba-tool', 'drs', 'showrepl']:
            return json.dumps({'repsFrom': [{'consecutive failures': 0, 'last success': '2026-10-23 12:00:00 UTC', 'naming context': 'DC=example,DC=test'}]})
        if args[:3] == ['samba-tool', 'computer', 'show']:
            readonly = self.readonly and args[3] != 'PRIMARY' and not self.joined
            return 'userAccountControl: ' + ('67112960' if readonly else '532480') + '\nprimaryGroupID: ' + ('521' if readonly else '516')
        if args[0] == 'systemctl':
            if args[1] == 'is-active':
                if args[2] == 'samba' and self.active:
                    return 'active'
                raise lifecycle.TransitionError('inactive')
            if args[1] == 'stop':
                self.active = False
            if args[1] == 'start':
                self.active = True
        if args[0] == 'dig':
            return 'status: NOERROR'
        if args[:4] == ['samba-tool', 'domain', 'backup', 'online']:
            directory = Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--targetdir=')))
            (directory / 'domain.tar.bz2').write_bytes(b'backup verified by native command')
        if args[:3] == ['samba-tool', 'domain', 'join']:
            stage = Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--targetdir=')))
            (stage / 'etc').mkdir()
            (stage / 'private').mkdir()
            (stage / 'sysvol').mkdir()
            (stage / 'private/sam.ldb').write_text('writable database')
            (stage / 'private/krb5.conf').write_text('[libdefaults]\n default_realm = EXAMPLE.TEST')
            (stage / 'etc/smb.conf').write_text('[global]\n private dir = ' + str(stage / 'private') + '\n[sysvol]\n path = ' + str(stage / 'sysvol'))
            self.joined = True
        if args[0] == 'smbclient' and 'mget *' in args[args.index('-c') + 1]:
            command = args[args.index('-c') + 1]
            directory = Path(command.split('lcd ', 1)[1].split(';')[0])
            (directory / 'primary-policy').write_text('authoritative policy')
        return ''


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.request = {'target_name': 'SECONDARY', 'target_hostname': 'secondary.example.test', 'realm': 'EXAMPLE.TEST',
                        'primary_name': 'PRIMARY', 'primary_hostname': 'primary.example.test', 'observer_hostname': 'primary.example.test',
                        'admin_username': 'administrator', 'admin_password': 'test-only-secret', 'rejoin_confirmed': True}
        live = self.root / 'var/lib/samba'
        (live / 'private').mkdir(parents=True)
        (live / 'sysvol').mkdir()
        (live / 'private/sam.ldb').write_text('readonly original database')
        (live / 'sysvol/old-policy').write_text('old policy')
        config = self.root / 'etc/samba/smb.conf'
        config.parent.mkdir(parents=True)
        config.write_text('[global]\n realm = EXAMPLE.TEST\n[sysvol]\n path = ' + str(live / 'sysvol'))

    def test_primary_handover_transfers_pdc_last_and_keeps_old_dc(self):
        runner = FakeController(self.root)
        steps = lifecycle.promote_primary(self.request, runner)
        transfers = [args for args in runner.calls if args[:3] == ['samba-tool', 'fsmo', 'transfer']]
        self.assertEqual(len(transfers), 7)
        self.assertIn('--role=pdc', transfers[-1])
        self.assertTrue(all(owner == 'SECONDARY' for owner in runner.roles.values()))
        self.assertFalse(any(args[:3] == ['samba-tool', 'domain', 'demote'] for args in runner.calls))
        self.assertFalse(any(args[:2] == ['systemctl', 'stop'] for args in runner.calls))
        self.assertFalse(any('seize' in args for args in runner.calls))
        self.assertIn('Antigo principal mantido', '\n'.join(steps))

    def test_primary_failure_reports_partial_transfer_without_seizing_or_demoting(self):
        runner = FakeController(self.root, fail=lambda args: args[:3] == ['samba-tool', 'fsmo', 'transfer'] and '--role=rid' in args)
        with self.assertRaisesRegex(lifecycle.TransitionError, 'funções já confirmadas'):
            lifecycle.promote_primary(self.request, runner)
        self.assertEqual(runner.roles['pdc'], 'PRIMARY')
        self.assertEqual(runner.roles['schema'], 'SECONDARY')
        self.assertFalse(any('seize' in args or 'demote' in args for args in runner.calls))

    def test_rodc_cannot_become_primary_directly(self):
        runner = FakeController(self.root, readonly=True)
        with self.assertRaisesRegex(lifecycle.TransitionError, 'DC gravável'):
            lifecycle.promote_primary(self.request, runner)
        self.assertFalse(any('transfer' in args for args in runner.calls))

    def test_unhealthy_replication_aborts_before_mutation(self):
        runner = FakeController(self.root)
        def bad_replication(args):
            if args[:3] == ['samba-tool', 'drs', 'showrepl']:
                return json.dumps({'repsFrom': [{'consecutive failures': 5, 'last success': 0}]})
            return runner(args)
        with self.assertRaisesRegex(lifecycle.TransitionError, 'Replicação'):
            lifecycle.promote_primary(self.request, bad_replication)
        self.assertFalse(any('transfer' in args for args in runner.calls))

    def test_plans_do_not_mutate_roles_or_services(self):
        for readonly in [False, True]:
            runner = FakeController(self.root, readonly=readonly)
            request = dict(self.request, dry_run=True)
            if readonly:
                lifecycle.promote_writable(request, self.root, runner)
            else:
                lifecycle.promote_primary(request, runner)
            self.assertFalse(any('transfer' in args or 'demote' in args or 'join' in args or 'stop' in args for args in runner.calls))

    def test_rodc_conversion_rejoins_and_syncs_sysvol_without_fsmo_transfer(self):
        runner = FakeController(self.root, readonly=True)
        steps = lifecycle.promote_writable(self.request, self.root, runner)
        self.assertTrue(runner.active)
        self.assertEqual((self.root / 'var/lib/samba/private/sam.ldb').read_text(), 'writable database')
        self.assertTrue((self.root / 'var/lib/samba/sysvol/primary-policy').exists())
        self.assertIn('127.0.0.1:5353', (self.root / 'etc/samba/smb.conf').read_text())
        self.assertFalse(any('transfer' in args for args in runner.calls))
        self.assertIn('--dns-backend=SAMBA_INTERNAL', next(args for args in runner.calls if args[:3] == ['samba-tool', 'domain', 'join']))
        self.assertIn('principal preservado', '\n'.join(steps))

    def test_rejoin_failure_keeps_invalid_rodc_stopped_and_preserves_recovery_files(self):
        runner = FakeController(self.root, readonly=True, fail=lambda args: args[:3] == ['samba-tool', 'domain', 'join'])
        with self.assertRaisesRegex(lifecycle.TransitionError, 'não reinicie a base antiga'):
            lifecycle.promote_writable(self.request, self.root, runner)
        self.assertFalse(runner.active)
        self.assertTrue(list((self.root / 'var/backups/samba').glob('rodc-before-writable-*/rodc-state/private/sam.ldb')))
        self.assertFalse(any(args[:2] == ['systemctl', 'start'] for args in runner.calls))

    def test_backup_failure_leaves_rodc_running(self):
        runner = FakeController(self.root, readonly=True, fail=lambda args: args[:4] == ['samba-tool', 'domain', 'backup', 'online'])
        with self.assertRaises(lifecycle.TransitionError):
            lifecycle.promote_writable(self.request, self.root, runner)
        self.assertTrue(runner.active)
        self.assertFalse(any('demote' in args for args in runner.calls))

    def test_explicit_conversion_consent_is_required(self):
        runner = FakeController(self.root, readonly=True)
        with self.assertRaisesRegex(lifecycle.TransitionError, 'Confirme'):
            lifecycle.promote_writable(dict(self.request, rejoin_confirmed=False), self.root, runner)
        self.assertFalse(any('backup' in args or 'demote' in args for args in runner.calls))


if __name__ == '__main__':
    unittest.main()
