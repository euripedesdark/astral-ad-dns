import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'samba-ad-dc'))
import pki_management as pki
from ad_operations import OperationError

class IndependentPKITests(unittest.TestCase):
    def test_rejects_unpinned_or_insecure_urls(self):
        for url in ['http://192.0.2.10:9444','https://127.0.0.1:9443',
                    'https://dc.example.test:9444/path','https://user:pass@dc.example.test:9444']:
            with self.subTest(url=url),self.assertRaises(OperationError):
                pki.inputs({'ca_url':url,'ca_fingerprint':'a'*64})

    def test_verify_does_not_touch_samba_domain(self):
        commands=[]
        def fake_run(args):
            commands.append(args)
            if 'bootstrap' in args:
                path=Path(next(x for x in args if x.startswith('STEPPATH='))[9:])/'certs/root_ca.crt'
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('public root')
            if args[:2]==['openssl','x509']:
                return 'sha256 Fingerprint='+':'.join(['ab']*32)
            return ''
        with patch.object(pki,'install_step'),patch.object(pki,'step_binary',return_value='/usr/bin/step'):
            result=pki.bootstrap({'ca_url':'https://192.0.2.10:9444','ca_fingerprint':'ab'*32},fake_run)
        self.assertEqual(result,b'public root')
        self.assertTrue(any('bootstrap' in c for c in commands))
        self.assertTrue(any('health' in c for c in commands))
        self.assertFalse(any('samba-tool' in c or 'systemctl' in c for c in commands))

    def test_mismatched_root_prevents_trust(self):
        commands=[]
        def fake_run(args):
            commands.append(args)
            if 'bootstrap' in args:
                path=Path(next(x for x in args if x.startswith('STEPPATH='))[9:])/'certs/root_ca.crt'
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('other root')
            if args[:2]==['openssl','x509']:return 'sha256 Fingerprint='+('cd'*32)
            return ''
        with patch.object(pki,'install_step'),patch.object(pki,'step_binary',return_value='/usr/bin/step'):
            with self.assertRaisesRegex(OperationError,'Fingerprint'):
                pki.bootstrap({'ca_url':'https://192.0.2.10:9444','ca_fingerprint':'ab'*32},fake_run)
        self.assertFalse(any('health' in c for c in commands))

    def test_status_does_not_mutate_host(self):
        with patch.object(pki,'step_binary',return_value=None),patch.object(pki.Path,'is_file',return_value=False):
            result=pki.execute({'action':'status'})
        self.assertTrue(result['success'])

if __name__=='__main__':
    unittest.main()
