"""RODC preflight must identify an existing local Samba AD database safely."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "samba-ad-dc"))
import provision_workflow as workflow
from ad_operations import OperationError


class LocalIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "var/lib/samba/private/sam.ldb"
        self.db.parent.mkdir(parents=True)
        self.db.write_text("fixture")
        self.config = self.root / "etc/samba/smb.conf"

    def runner(self, name="", realm="", rootdse=""):
        def run(args):
            if args[0] == "testparm":
                return name if "netbios name" in args else realm
            if args[0] == "ldbsearch":
                return rootdse
            raise OperationError("unexpected command: " + repr(args))
        return run

    def test_recovers_identity_from_rootdse_when_smb_conf_missing(self):
        text = ("dn: @ROOTDSE\n"
                "defaultNamingContext: DC=srvcloud,DC=cloud\n"
                "dsServiceName: CN=NTDS Settings,CN=RODC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=srvcloud,DC=cloud\n")
        name, realm, source = workflow.local_ad_identity(
            self.root, self.runner(rootdse=text), self.config)
        self.assertEqual((name, realm, source), ("RODC2", "SRVCLOUD.CLOUD", "rootdse"))

    def test_blocks_inconsistent_database_identity(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text("[global]")
        text = ("defaultNamingContext: DC=srvcloud,DC=cloud\n"
                "dsServiceName: CN=NTDS Settings,CN=DC-ERP,CN=Servers,CN=Default-First-Site-Name\n")
        with self.assertRaisesRegex(OperationError, "inconsistente"):
            workflow.local_ad_identity(
                self.root, self.runner(name="RODC2", realm="SRVCLOUD.CLOUD", rootdse=text),
                self.config)

    def test_blocks_unidentified_database_in_provisioning_guard(self):
        name, realm, source = workflow.local_ad_identity(
            self.root, self.runner(), self.config)
        self.assertEqual((name, realm, source), ("", "", "config"))
        self.assertTrue(not name or not realm)

    def test_integration_has_same_guard_in_integrated_install(self):
        integrated = (Path(__file__).resolve().parents[1] / "samba-ad-dc/provision_dc1.py").read_text()
        self.assertIn("def local_ad_identity(", integrated)
        self.assertIn("old_name, old_realm, identity_source = local_ad_identity(", integrated)
        self.assertIn("Limpeza bloqueada para proteger o primario.", integrated)

if __name__ == "__main__":
    unittest.main()
