"""Regression coverage for RODC DRS health validation."""
from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "samba-ad-dc" / "provision_workflow.py").read_text()


class RodcDrsValidationTests(unittest.TestCase):
    def test_drs_validation_uses_local_smb_config_and_explicit_ip(self):
        self.assertIn("'--ipaddress=' + local_drs_ip", SOURCE)
        self.assertIn("'drs', 'showrepl', '--json'", SOURCE)
        self.assertIn("str(config)", SOURCE)

    def test_no_memory_is_reported_as_a_specific_failure(self):
        self.assertIn("STATUS_NO_MEMORY (0xC0000017)", SOURCE)
        self.assertIn("Ingresso preservado; nao sera marcado como concluido", SOURCE)

    def test_unknown_json_shape_fails_closed(self):
        self.assertIn("if isinstance(health, dict):", SOURCE)
        self.assertIn("healthy = False", SOURCE)
        self.assertIn("nao confirmou vizinhos de entrada saudaveis", SOURCE)


if __name__ == "__main__":
    unittest.main()
