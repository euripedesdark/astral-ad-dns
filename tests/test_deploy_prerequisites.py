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

    def test_missing_cargo_triggers_install_before_deploy(self):
        installed=set()
        commands=[]
        def which(name):
            return None if name=='cargo' and name not in installed else '/usr/bin/'+name
        def runner(command,**kwargs):
            commands.append((command,kwargs))
            if command[:3]==['dnf','install','-y']:
                installed.add('cargo')
            return True
        with patch.object(deploy.shutil,'which',side_effect=which),\
             patch.object(deploy,'detect_host_distribution',return_value=('almalinux','10',True)),\
             patch.object(deploy,'run_cmd',side_effect=runner),\
             patch.object(deploy,'log_warning'),\
             patch.object(deploy,'log_success'):
            deploy.check_prerequisites()
        self.assertIn((['dnf','install','-y','cargo'],{'use_sudo':True}),commands)

    def test_missing_rust_cargo_node_npm_installs_once_with_sudo(self):
        missing={'rustc','cargo','node','npm'}
        installed=set()
        calls=[]
        def which(name):
            return None if name in missing and name not in installed else '/usr/bin/'+name
        def runner(args,**kwargs):
            calls.append((args,kwargs))
            if args[:3]==['dnf','install','-y']:
                installed.update(missing)
            return True
        with patch.object(deploy.shutil,'which',side_effect=which),\
             patch.object(deploy,'detect_host_distribution',return_value=('almalinux','10',True)),\
             patch.object(deploy,'run_cmd',side_effect=runner),\
             patch.object(deploy,'log_warning'),\
             patch.object(deploy,'log_success'):
            deploy.check_prerequisites()
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][0],['dnf','install','-y','cargo','nodejs','npm','rust'])
        self.assertTrue(calls[0][1]['use_sudo'])

    def test_arch_uses_rust_not_rustc_package(self):
        installed=set()
        def which(name):
            return None if name in ('cargo','rustc') and name not in installed else '/usr/bin/'+name
        commands=[]
        def runner(args,**kwargs):
            commands.append((args,kwargs))
            installed.update(('cargo','rustc'))
            return True
        with patch.object(deploy.shutil,'which',side_effect=which),\
             patch.object(deploy,'detect_host_distribution',return_value=('arch','',False)),\
             patch.object(deploy,'run_cmd',side_effect=runner),\
             patch.object(deploy,'log_warning'),\
             patch.object(deploy,'log_success'):
            deploy.check_prerequisites()
        self.assertEqual(commands[0][0],['pacman','-S','--needed','--noconfirm','rust'])
        self.assertTrue(commands[0][1]['use_sudo'])

    def test_existing_toolchain_is_not_installed_again(self):
        with patch.object(deploy.shutil,'which',return_value='/usr/bin/tool'),\
             patch.object(deploy,'run_cmd') as run,\
             patch.object(deploy,'log_success'):
            deploy.check_prerequisites()
        run.assert_not_called()

if __name__=='__main__':
    unittest.main()
