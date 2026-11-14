"""Ensure DC1, DC2 and RODC actually use their idempotent iptables flow."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
DC1=ROOT/'samba-ad-dc/provision_dc1.py'
JOIN=ROOT/'samba-ad-dc/provision_workflow.py'
COMMON=ROOT/'samba-ad-dc/provision_system.py'
API=ROOT/'src/api/provision.rs'

class FirewallParityTests(unittest.TestCase):
    def test_all_three_roles_call_firewall_preparation(self):
        for path in (DC1,JOIN):
            with self.subTest(path=path.name):
                tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
                execute=next(node for node in tree.body
                             if isinstance(node,ast.FunctionDef) and node.name=='execute')
                calls=[node for node in ast.walk(execute) if isinstance(node,ast.Call)]
                self.assertTrue(any(isinstance(call.func,ast.Name)
                                    and call.func.id=='configure_firewall' for call in calls))

    def test_both_firewall_sources_include_high_udp_tcp(self):
        for path in (DC1,COMMON):
            with self.subTest(path=path.name):
                source=path.read_text(encoding='utf-8')
                self.assertIn("['-p','tcp','--dport','49152:65535','-j','ACCEPT']",source)
                self.assertIn("['-p','udp','--dport','49152:65535','-j','ACCEPT']",source)
                self.assertIn("['iptables','-C','INPUT']",source)
                self.assertIn("['iptables','-I','INPUT',position]",source)
                self.assertIn("astral-ad-firewall.service",source)

    def test_wizard_preflight_shows_both_protocols(self):
        source=API.read_text(encoding='utf-8')
        self.assertIn('(49152, "tcp",',source)
        self.assertIn('(49152, "udp",',source)
        self.assertIn('"49152:65535".to_string()',source)

if __name__=='__main__':
    unittest.main()
