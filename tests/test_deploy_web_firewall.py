"""Regressions for deployment systemd registration and web firewall preflight."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'deploy_ad_dns.py'
spec=importlib.util.spec_from_file_location('astral_deploy_systemd',SOURCE)
deploy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

class FirewallTests(unittest.TestCase):
    def test_empty_accept_chain_is_already_open(self):
        calls=[]
        def runner(cmd,**kw):
            calls.append(cmd)
            if cmd[:3]==['iptables','-S','INPUT']:
                return '-P INPUT ACCEPT'
            if cmd[:3]==['iptables','-C','INPUT']:
                return False
            raise AssertionError(cmd)
        with patch.object(deploy.shutil,'which',return_value='/usr/sbin/iptables'), \
             patch.object(deploy,'run_cmd',side_effect=runner), \
             patch.object(deploy,'log_success'):
            deploy.verify_web_firewall()
        self.assertFalse(any('-I' in cmd for cmd in calls))

    def test_blocking_input_chain_inserts_single_accept(self):
        calls=[]
        state={'added':False}
        def runner(cmd,**kw):
            calls.append(cmd)
            if cmd[:3]==['iptables','-S','INPUT']:
                return '-P INPUT DROP'
            if cmd[:3]==['iptables','-C','INPUT']:
                return state['added']
            if cmd[:3]==['iptables','-I','INPUT']:
                state['added']=True
                return True
            raise AssertionError(cmd)
        with patch.object(deploy.shutil,'which',return_value='/usr/sbin/iptables'), \
             patch.object(deploy,'run_cmd',side_effect=runner), \
             patch.object(deploy,'log_success'), \
             patch.object(deploy,'log_warning'):
            deploy.verify_web_firewall()
            deploy.verify_web_firewall()
        self.assertEqual(sum(cmd[:3]==['iptables','-I','INPUT'] for cmd in calls),1)

    def test_missing_iptables_only_warns_without_mutation(self):
        with patch.object(deploy.shutil,'which',return_value=None), \
             patch.object(deploy,'log_warning') as warning, \
             patch.object(deploy,'run_cmd') as run:
            deploy.verify_web_firewall()
        warning.assert_called_once()
        run.assert_not_called()

if __name__=='__main__':
    unittest.main()
