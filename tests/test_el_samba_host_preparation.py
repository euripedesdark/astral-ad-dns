"""No-network tests of distro detection and safe root-only Samba AD preparation."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SOURCE=pathlib.Path(__file__).resolve().parents[1]/"deploy_ad_dns.py"
spec=importlib.util.spec_from_file_location("prepare_astral_ad",SOURCE)
deploy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class HostPreparationTests(unittest.TestCase):
    def make_release(self, text):
        file=tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",delete=False)
        file.write(text)
        file.close()
        self.addCleanup(pathlib.Path(file.name).unlink)
        return file.name

    def test_distribution_mapping(self):
        for distro,ver,is_el in [
            ("almalinux","10",True),("rocky","9",True),
            ("rhel","10",True),("fedora","44",False),
            ("fedora","45",False),("arch","",False),
        ]:
            with self.subTest(distro=distro,ver=ver):
                text=f'ID={distro}\nVERSION_ID="{ver}.0"\n'
                found=deploy.detect_host_distribution(self.make_release(text))
                self.assertEqual(found[0],distro)
                self.assertEqual(found[1],ver)
                self.assertEqual(found[2],is_el)

    def mock_preparation(self, release, existing_repo=False):
        commands=[]
        self.repo_text=""
        def fake_run(args, **kw):
            commands.append((args,kw))
            if args and args[0]=="install" and args[-1]=="/etc/yum.repos.d/tissamba.repo":
                self.repo_text=pathlib.Path(args[-2]).read_text(encoding="utf-8")
            if args[:3]==["rpm","-q","samba-winexe"]:
                return False
            if args[:3]==["rpm","-q","epel-release"]:
                return False
            if args and args[0]=="cat":
                return ("[tis-samba]\nname=tis-samba\n"
                        "baseurl=https://samba.tranquil.it/redhat10/samba-4.24/\n"
                        "gpgcheck=1\n"
                        "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-TISSAMBA-10")
            return True
        real_exist=deploy.os.path.exists
        def fake_exist(path):
            return existing_repo if path=="/etc/yum.repos.d/tissamba.repo" else real_exist(path)
        with patch.object(deploy.shutil,"which",return_value="/usr/sbin/tool"), \
             patch.object(deploy.os.path,"isfile",return_value=False), \
             patch.object(deploy.os.path,"exists",side_effect=fake_exist), \
             patch.object(deploy,"run_cmd",side_effect=fake_run), \
             patch.object(deploy,"log_header"), \
             patch.object(deploy,"log_success"), \
             patch.object(deploy,"log_warning"):
            deploy.prepare_ad_packages(release)
        return commands

    def test_almalinux10_repo_install_is_elevated_and_has_required_packages(self):
        commands=self.mock_preparation(self.make_release("ID=almalinux\nVERSION_ID=10.2\n"))
        self.assertTrue(all(kw.get("use_sudo") for cmd,kw in commands))
        joined="\n".join(" ".join(cmd) for cmd,_ in commands)
        self.assertIn("RPM-GPG-KEY-TISSAMBA-10",joined)
        self.assertIn("dnf config-manager --set-enabled crb",joined)
        self.assertIn("epel-release-latest-10.noarch.rpm",joined)
        self.assertIn("--enablerepo=crb install -y samba samba-dc",joined)
        self.assertIn("python3-setproctitle",joined)
        self.assertNotIn("systemctl start samba",joined)
        self.assertNotIn("--allowerasing",joined)

    def test_rhel9_uses_subscription_manager_and_versioned_key(self):
        commands=self.mock_preparation(self.make_release("ID=rhel\nVERSION_ID=9.6\n"))
        joined="\n".join(" ".join(cmd) for cmd,_ in commands)
        self.assertIn("subscription-manager repos --enable codeready-builder-for-rhel-9-",joined)
        self.assertIn("RPM-GPG-KEY-TISSAMBA-9",joined)
        self.assertIn("redhat9/samba-4.24/",self.repo_text)

    def test_existing_equivalent_repo_without_enabled_is_preserved(self):
        commands=self.mock_preparation(self.make_release("ID=almalinux\nVERSION_ID=10\n"), True)
        self.assertFalse(any(cmd[0]=="install" and cmd[-1]=="/etc/yum.repos.d/tissamba.repo" for cmd,_ in commands))

    def test_fedora_and_arch_make_no_changes(self):
        for distro in ("fedora","arch"):
            release=self.make_release(f"ID={distro}\nVERSION_ID=45\n")
            with patch.object(deploy,"run_cmd") as run,patch.object(deploy,"log_success"):
                deploy.prepare_ad_packages(release)
            run.assert_not_called()

    def test_existing_ad_aborts_before_any_commands(self):
        release=self.make_release("ID=almalinux\nVERSION_ID=10\n")
        with patch.object(deploy.os.path,"isfile",return_value=True), \
             patch.object(deploy,"log_error"), \
             patch.object(deploy,"run_cmd") as run:
            with self.assertRaises(SystemExit):
                deploy.prepare_ad_packages(release)
        run.assert_not_called()


if __name__=="__main__":
    unittest.main()
