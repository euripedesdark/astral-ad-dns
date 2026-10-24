import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid

SPEC = importlib.util.spec_from_file_location('forensics', Path(__file__).resolve().parents[1] / 'samba-ad-dc/ad_forensics.py')
forensics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forensics)


class Collector:
    def __init__(self, root, changed=False, unavailable=None):
        self.root = root
        self.changed = changed
        self.unavailable = unavailable
        self.calls = []
        self.sysvol = root / 'sysvol'
        self.sysvol.mkdir(exist_ok=True)
        (self.sysvol / 'GPT.INI').write_text('policy')

    def __call__(self, args):
        self.calls.append(args)
        if self.unavailable and self.unavailable(args):
            raise RuntimeError('injected missing dependency')
        if args[0] == 'hostname': return 'dc.example.test\n'
        if args[0] == 'testparm':
            if '--parameter-name=realm' in args: return 'EXAMPLE.TEST\n'
            if '--parameter-name=private dir' in args: return str(self.root / 'private')
            return str(self.sysvol)
        if args[0] == 'timedatectl': return 'yes\n'
        if args[0] == 'getfacl':
            return '\n\n'.join('# file: ' + str(path) + '\n# owner: 0\nuser::rwx\ngroup::r-x\nother::r-x' for path in [self.sysvol, self.sysvol / 'GPT.INI'])
        if args[0] == 'ldbsearch':
            base = args[args.index('-b') + 1]
            if not base:
                return 'dn:\nnamingContexts: DC=example,DC=test\ndefaultNamingContext: DC=example,DC=test\n\n'
            guid = base64.b64encode(uuid.UUID('aaaaaaaa-1111-2222-3333-444444444444').bytes_le).decode()
            user_dn = 'CN=Renamed,DC=example,DC=test' if self.changed else 'CN=Administrator,DC=example,DC=test'
            acl = base64.b64encode(b'new ACL' if self.changed else b'old ACL').decode()
            return ('dn: DC=example,DC=test\nobjectGUID: domain-guid\nobjectSid: S-1-5-21-111-222-333\nobjectClass: domainDNS\n\n'
                    f'dn: {user_dn}\nobjectGUID:: {guid}\nobjectClass: user\nsAMAccountName: Administrator\nadminCount: 1\nuserAccountControl: ' + ('514' if self.changed else '512') +
                    f'\nnTSecurityDescriptor:: {acl}\n\n'
                    'dn: CN=Domain Admins,DC=example,DC=test\nobjectGUID: group-guid\nobjectClass: group\nobjectSid: S-1-5-21-111-222-333-512\nmember: ' + user_dn + '\n\n')
        return 'native evidence\n'


class ForensicsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / 'evidence'

    def test_capture_comparison_and_html_end_to_end(self):
        first = forensics.execute({'action': 'capture', 'analyst': 'tester', 'label': 'Reference'}, self.store, Collector(self.root))
        second = forensics.execute({'action': 'capture', 'analyst': '<script>alert(1)</script>', 'baseline_id': first['snapshot_id']}, self.store, Collector(self.root, changed=True))
        report = forensics.execute({'action': 'report', 'report_id': second['report_id']}, self.store)
        html = forensics.execute({'action': 'html', 'report_id': second['report_id']}, self.store)['html']
        self.assertTrue(report['comparison']['available'])
        self.assertEqual(report['comparison']['summary']['removed'], 0)
        self.assertEqual(report['comparison']['summary']['added'], 0)
        self.assertEqual(report['comparison']['summary']['disabled_accounts'], 1)
        self.assertEqual(report['comparison']['summary']['permissions_changed'], 1)
        self.assertIn('<!doctype html>', html)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertEqual(len(forensics.overview(self.store)['reports']), 2)
        for path in self.store.rglob('*'):
            if path.is_file(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_windows_and_ldap_timestamps_are_readable_in_utc(self):
        self.assertEqual(forensics.ad_time('116444736000000000'), '1970-01-01T00:00:00+00:00')
        self.assertEqual(forensics.ad_time('20261023212200.0Z'), '2026-10-23T21:22:00+00:00')
        self.assertIn('Não definido', forensics.ad_time('0'))

    def test_folded_base64_guid_and_unicode_dn(self):
        guid = uuid.UUID('12345678-9abc-def0-1234-56789abcdef0')
        encoded = base64.b64encode(guid.bytes_le).decode()
        dn = base64.b64encode('CN=José,DC=test'.encode()).decode()
        records = forensics.parse_ldif(f'dn:: {dn}\nobjectGUID:: {encoded[:10]}\n {encoded[10:]}\nmember: b\nmember: a\nmember: a\n\n')
        self.assertEqual(records[0]['objectguid'], [str(guid)])
        self.assertEqual(records[0]['dn'], ['CN=José,DC=test'])
        self.assertEqual(records[0]['member'], ['a', 'b'])

    def test_incomplete_collection_does_not_invent_mass_deletion(self):
        runner = Collector(self.root)
        old = forensics.capture({}, self.store, runner)
        new = forensics.capture({}, self.store, Collector(self.root, unavailable=lambda args: args[0] == 'ldbsearch' and '(objectClass=*)' in args))
        comparison = forensics.compare(old, new)
        self.assertFalse(comparison['available'])
        self.assertEqual(comparison['removed'], [])
        self.assertEqual(new['status'], 'partial')

    def test_manifest_tampering_blocks_baseline_and_report_loading(self):
        result = forensics.execute({'action': 'capture'}, self.store, Collector(self.root))
        snapshot = self.store / 'snapshots' / result['snapshot_id'] / 'snapshot.json'
        snapshot.write_text(snapshot.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'Integridade'):
            forensics.load_snapshot(result['snapshot_id'], self.store)
        report = self.store / 'reports' / result['report_id'] / 'report.html'
        report.write_text('<script>bad</script>')
        with self.assertRaisesRegex(ValueError, 'Integridade'):
            forensics.execute({'action': 'html', 'report_id': result['report_id']}, self.store)

    def test_path_traversal_and_external_ldif_references_are_rejected(self):
        with self.assertRaises(ValueError):
            forensics.execute({'action': 'report', 'report_id': '../../etc/passwd'}, self.store)
        with self.assertRaises(ValueError):
            forensics.parse_ldif('dn: test\nobjectGUID:< file:///etc/passwd\n')

    def test_nested_privileged_membership_and_historical_admincount(self):
        objects = {
            'root': {'dn': ['CN=Admins'], 'objectclass': ['group'], 'objectsid': ['S-1-5-32-544'], 'member': ['CN=Nested']},
            'nested': {'dn': ['CN=Nested'], 'objectclass': ['group'], 'member': ['CN=User']},
            'user': {'dn': ['CN=User'], 'objectclass': ['user'], 'samaccountname': ['user']},
            'historical': {'dn': ['CN=OldAdmin'], 'objectclass': ['user'], 'admincount': ['1']},
        }
        accounts = {item['id']: item for item in forensics.privileged(objects)}
        self.assertIn('user', accounts)
        self.assertIn('histórico', accounts['historical']['reasons'][0])

    def test_different_domain_and_host_block_comparison(self):
        old = forensics.capture({}, self.store, Collector(self.root))
        for field in ['domain_sid', 'realm', 'host']:
            new = copy.deepcopy(old)
            new[field] = 'different'
            self.assertFalse(forensics.compare(old, new)['available'])

    def test_attribute_allowlist_does_not_request_passwords_or_keys(self):
        runner = Collector(self.root)
        forensics.capture({}, self.store, runner)
        for args in runner.calls:
            self.assertFalse(set(arg.lower() for arg in args) & {'unicodepwd', 'supplementalcredentials', 'ntpwdhistory', 'lmpwdhistory', '*'})
            self.assertFalse(set(args) & {'--fix', '--yes', 'restore', 'setpassword', 'resync'})

    def test_missing_sysvol_acl_and_clock_are_explicit(self):
        result = forensics.execute({'action': 'capture'}, self.store, Collector(self.root, unavailable=lambda args: args[0] in ['getfacl', 'timedatectl']))
        report = forensics.execute({'action': 'report', 'report_id': result['report_id']}, self.store)
        self.assertEqual(report['snapshot']['status'], 'partial')
        self.assertFalse(report['snapshot']['sysvol_complete'])
        self.assertTrue(any('NTP' in warning for warning in report['limitations']))


if __name__ == '__main__':
    unittest.main()
