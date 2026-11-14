"""Prevent publishing syntactically broken provision stacks to production."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
STACKS = [
    ROOT / "samba-ad-dc" / "provision_dc1.py",
    ROOT / "samba-ad-dc" / "provision_workflow.py",
    ROOT / "samba-ad-dc" / "ad_operations.py",
]

class StackSyntaxRegression(unittest.TestCase):
    def test_all_python_stacks_parse_before_deploy(self):
        for path in STACKS:
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_dc1_stack_has_single_entrypoint_and_no_appended_workflow(self):
        source = STACKS[0].read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(STACKS[0]))
        self.assertEqual(sum(isinstance(node, ast.If)
                             and isinstance(node.test, ast.Compare)
                             and isinstance(node.test.left, ast.Name)
                             and node.test.left.id == "__name__"
                             for node in tree.body), 1)
        self.assertNotIn("\n,'',text)", source)
        self.assertEqual(sum(isinstance(node, ast.FunctionDef)
                             and node.name == "execute" for node in tree.body), 1)

if __name__ == "__main__":
    unittest.main()
