"""Regression checks: an unprovisioned host must never inherit a developer's AD."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class DomainDiscoveryTests(unittest.TestCase):
    def test_no_fixed_previous_domain_in_dashboard_or_provision_checks(self):
        for name in ("web/src/App.jsx", "src/api/status.rs", "src/api/provision.rs"):
            content=(ROOT/name).read_text(encoding="utf-8").lower()
            self.assertNotIn("srvcloud.cloud",content,name)
            self.assertNotIn("dc-erp",content,name)

    def test_status_requires_real_ad_database(self):
        content=(ROOT/"src/api/status.rs").read_text(encoding="utf-8")
        self.assertIn('Path::new("/var/lib/samba/private/sam.ldb").is_file()',content)
        self.assertIn('if !ad_configured {',content)
        self.assertIn("realm.clear()",content)
        self.assertIn("let mut forest_level = String::new()",content)

    def test_wizard_has_no_prefilled_realm_or_workgroup(self):
        content=(ROOT/"web/src/App.jsx").read_text(encoding="utf-8")
        self.assertIn("const [realm, setRealm] = useState('')",content)
        self.assertIn("const [workgroup, setWorkgroup] = useState('')",content)
        self.assertIn("'Domínio não provisionado'",content)

if __name__=="__main__":
    unittest.main()
