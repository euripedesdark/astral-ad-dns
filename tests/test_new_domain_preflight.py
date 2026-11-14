"""The new-domain wizard validates existing host dependencies before mutation."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'samba-ad-dc/provision_dc1.py'
spec=importlib.util.spec_from_file_location('new_domain_stack', SOURCE)
stack=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)


class NewDomainPreflightTests(unittest.TestCase):
    def test_missing_samba_package_blocks_before_running_commands(self):
        calls=[]
        with patch.object(stack.shutil,'which',side_effect=lambda name: None if name=='samba-tool' else '/usr/bin/'+name):
            with self.assertRaisesRegex(stack.OperationError,'samba-tool'):
                stack.verify_new_domain_prerequisites(Path('/'),lambda args: calls.append(args) or '',False,[])
        self.assertEqual(calls,[])

    def test_python_samba_bindings_checked_without_install(self):
        calls=[]
        with patch.object(stack.shutil,'which',return_value='/usr/bin/tool'):
            stack.verify_new_domain_prerequisites(Path('/'),lambda args: calls.append(args) or '',False,[])
        self.assertTrue(any(args[:2]==['/usr/bin/python3','-c'] for args in calls))
        self.assertIn(['iptables-save'],calls)
        self.assertFalse(any(args[0] in ('apt-get','dnf','yum','pacman','zypper') for args in calls))

    def test_bind_dependency_required_only_if_selected(self):
        calls=[]
        with patch.object(stack.shutil,'which',side_effect=lambda name: None if name=='named' else '/usr/bin/'+name):
            stack.verify_new_domain_prerequisites(Path('/'),lambda args: calls.append(args) or '',False,[])
            with self.assertRaisesRegex(stack.OperationError,'named'):
                stack.verify_new_domain_prerequisites(Path('/'),lambda args: calls.append(args) or '',True,[])

    def test_firewall_inspection_and_verification_are_read_only(self):
        calls=[]
        def run(args):
            calls.append(args)
            if args[:3]==['iptables','-C','INPUT'] and '--dport' in args:
                raise stack.OperationError('missing rule')
            return ''
        req={'domain_role':'DC'}
        rules=stack.verify_new_domain_firewall(req,run,[])
        self.assertTrue(rules)
        self.assertFalse(any(args[:2]==['iptables','-I'] for args in calls))
        with self.assertRaises(stack.OperationError):
            stack.verify_firewall_after_prepare(rules,run,[])

    def test_new_domain_installs_step_ca_after_samba_active(self):
        source=SOURCE.read_text()
        # Covers the generated monolithic workflow; detailed behavior also
        # requires an integration test on a disposable AD test host.
        self.assertLess(source.index("run(['systemctl', 'restart', name])"),
                        source.index("manifest['phase']='primary_pki_after_samba'"))
        self.assertIn("verify_new_domain_prerequisites(root,run",source)
        self.assertIn("verify_firewall_after_prepare(firewall_to_verify,run,steps)",source)

if __name__=='__main__':
    unittest.main()
