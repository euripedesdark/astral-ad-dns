"""Deploy must report missing Samba AD DC runtime without blocking web console."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

source=Path(__file__).resolve().parents[1]/'deploy_ad_dns.py'
spec=importlib.util.spec_from_file_location('deploy_ad_dns',source)
deploy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

class DeployPrerequisitesTests(unittest.TestCase):
    def test_missing_ad_daemon_is_warning_for_web_deploy(self):
        logs=[]
        def which(name):
            return None if name in ('samba','winbindd') else '/usr/bin/'+name
        with patch.object(deploy.shutil,'which',side_effect=which),\
             patch.object(deploy,'log_warning',side_effect=logs.append),\
             patch.object(deploy,'log_success'):
            deploy.check_prerequisites()
        self.assertTrue(any("Daemon do Samba AD DC ausente" in line for line in logs))
        self.assertTrue(any("winbindd" in line for line in logs))

    def test_missing_cargo_stops_before_deploy(self):
        with patch.object(deploy.shutil,'which',side_effect=lambda name:None if name=='cargo' else '/usr/bin/'+name),\
             patch.object(deploy,'log_error'),\
             self.assertRaises(SystemExit):
            deploy.check_prerequisites()

if __name__=='__main__':
    unittest.main()
