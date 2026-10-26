import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'samba-ad-dc'))
from provision_tls import prepare_existing_tls, install_existing_tls
from ad_operations import OperationError

class ExistingTLS(unittest.TestCase):
    def test_real_openssl_validation_and_install_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=dc2.example.test','-addext','subjectAltName=DNS:dc2.example.test','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            def run(args):
                r=subprocess.run(args,capture_output=True,text=True)
                if r.returncode:raise OperationError(r.stderr)
                return r.stdout
            request=dict(tls_mode='existing',tls_cert_path=str(cert),tls_key_path=str(key),tls_ca_path=str(cert),netbios_name='DC2',realm='EXAMPLE.TEST')
            prepare_existing_tls(request,root,run,[])
            cert.unlink();key.unlink()
            pairs=install_existing_tls(request,root)
            self.assertTrue(pairs)
            self.assertEqual((root/'etc/samba/tls/dc.key').stat().st_mode&0o777,0o600)
            request['netbios_name']='WRONG'
            request.update(tls_cert_path=str(root/'etc/samba/tls/dc.crt'),tls_key_path=str(root/'etc/samba/tls/dc.key'),tls_ca_path=str(root/'etc/samba/tls/ca.crt'))
            with self.assertRaises(OperationError):prepare_existing_tls(request,root,run,[])
    def test_auto_does_not_require_step_ca_or_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            request={};steps=[]
            prepare_existing_tls(request,Path(directory),lambda _:self.fail('no openssl needed'),steps)
            self.assertNotIn('_existing_tls',request)
            self.assertTrue(steps)
    def test_explicit_mode_requires_complete_material(self):
        with self.assertRaises(OperationError):
            prepare_existing_tls({'tls_mode':'existing'},Path('/'),None,[])
