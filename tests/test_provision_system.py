import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'samba-ad-dc'))
import provision_system as system
import provision_pki as pki
from ad_operations import OperationError


class SystemTests(unittest.TestCase):
    def test_ca_automatically_chooses_free_port_without_touching_nginx(self):
        with tempfile.TemporaryDirectory() as directory:
            listeners='tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("nginx"))\n'
            self.assertEqual(system.allocate_ca_port(Path(directory),lambda _:listeners,8443),9443)
            listeners+='tcp LISTEN 0 128 0.0.0.0:9443 0.0.0.0:* users:(("another"))\n'
            self.assertEqual(system.allocate_ca_port(Path(directory),lambda _:listeners,8443),10443)
            self.assertEqual(system.allocate_ca_port(Path(directory),lambda _:listeners,12443),12443)

    def test_missing_packages_are_installed_by_detected_manager(self):
        for manager in ['dnf','yum','apt-get','pacman','zypper']:
            with self.subTest(manager=manager),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);installed=False;calls=[]
                def which(name):
                    if name in ['dnf','yum','apt-get','pacman','zypper']:return '/usr/bin/'+name if name==manager else None
                    return '/usr/bin/'+name if installed or name!='dig' else None
                def run(args):
                    nonlocal installed
                    calls.append(args)
                    if 'install' in args or '-S' in args:installed=True
                    return ''
                with patch.object(system.shutil,'which',side_effect=which):
                    system.install_dependencies(root,run,False,[])
                self.assertTrue(installed)
                self.assertFalse((root/'usr/sbin/policy-rc.d').exists())
                self.assertTrue(any('dnsutils' in args or 'bind-utils' in args or 'bind' in args for args in calls))
    def test_package_install_failure_restores_debian_service_start_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);policy=root/'usr/sbin/policy-rc.d';policy.parent.mkdir(parents=True);policy.write_text('existing policy')
            def which(name):return '/usr/bin/apt-get' if name=='apt-get' else None
            def run(args):raise OperationError('repository unavailable')
            with patch.object(system.shutil,'which',side_effect=which),self.assertRaises(OperationError):
                system.install_dependencies(root,run,True,[])
            self.assertEqual(policy.read_text(),'existing policy')
    def test_ca_port_is_configurable_and_auth_service_8443_is_not_opened_as_ca(self):
        rules=system.firewall_rules('DC',True,9443)
        self.assertIn(['-p','tcp','--dport','9443','-j','ACCEPT'],rules)
        self.assertNotIn(['-p','tcp','--dport','8443','-j','ACCEPT'],rules)
    def test_existing_ca_is_never_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'etc/step-ca/config/ca.json';config.parent.mkdir(parents=True);config.write_text('{}')
            req={'setup_step_ca':True,'initialize_ca':True,'kind':'new','cert_password':'pki-secret','host_ip':'192.0.2.20','hostname_fqdn':'dc.example.test','realm':'EXAMPLE.TEST'}
            calls=[]
            with patch.object(pki.shutil,'which',return_value='/usr/bin/step'),self.assertRaisesRegex(OperationError,'Ja existe uma CA'):
                pki.configure_pki(req,root,lambda args:calls.append(args) or '', 'samba',[])
            self.assertEqual(config.read_text(),'{}')
            self.assertFalse(any('init' in args for args in calls))
    def test_nginx_listener_conflict_stops_ca_before_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);calls=[]
            req={'setup_step_ca':True,'initialize_ca':True,'kind':'new','cert_password':'pki-secret','host_ip':'192.0.2.20','hostname_fqdn':'dc.example.test','realm':'EXAMPLE.TEST','ca_port':8443}
            def run(args):calls.append(args);return 'tcp LISTEN 0 128 0.0.0.0:8443 users:(("nginx"))' if args[0]=='ss' else ''
            with patch.object(pki.shutil,'which',return_value='/usr/bin/step'),self.assertRaisesRegex(OperationError,'ocupada'):
                pki.configure_pki(req,root,run,'samba',[])
            self.assertFalse(any('init' in args or args[:2]==['systemctl','stop'] for args in calls))
    def test_existing_local_ca_issues_cert_with_temporary_secret_and_installs_renewal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'etc/step-ca/config/ca.json';config.parent.mkdir(parents=True);config.write_text(json.dumps({'address':':9443'}))
            ca=root/'etc/step-ca/certs/root_ca.crt';ca.parent.mkdir();ca.write_text('trusted root')
            req={'setup_step_ca':True,'initialize_ca':False,'kind':'configure','cert_password':'pki-secret','host_ip':'192.0.2.20','hostname_fqdn':'dc.example.test','netbios_name':'DC','realm':'EXAMPLE.TEST'}
            def run(args):
                if args[:3]==['step','ca','certificate']:
                    Path(args[4]).write_text('signed certificate');Path(args[5]).write_text('private key')
                return ''
            with patch.object(pki.shutil,'which',return_value='/usr/bin/step'):
                pairs=pki.configure_pki(req,root,run,'samba',[])
            self.assertEqual((root/'etc/samba/tls/dc.key').stat().st_mode & 0o777,0o600)
            self.assertFalse(list((root/'etc/samba/tls').glob('astral-pki-*')))
            self.assertTrue((root/'etc/systemd/system/astral-ad-tls-renew.timer').exists())
            self.assertNotIn('pki-secret',(root/'etc/astral-ad-dns/tls-renew.json').read_text())
            self.assertIn(('tls enabled','yes'),pairs)

if __name__=='__main__':unittest.main()
