"""Tests for safe idempotent DC demotion and member finalization."""
import ast
import io
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "samba-ad-dc"))
import ad_operations as ops


def load_helpers():
    tree = ast.parse(ops.DEMOTE_PROGRAM)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    code = compile(ast.Module(body=nodes, type_ignores=[]), "<demote-helpers>", "exec")
    context = {
        "request": {"target_name": "VMWARE", "admin_username": "administrator",
                    "admin_password": "SensitiveSecret!" },
        "name": "VMWARE", "partner": "dc-erp.srvcloud.cloud",
        "admin": "administrator", "os": os,
        "subprocess": __import__("subprocess"), "re": __import__("re"),
        "pathlib": __import__("pathlib"), "shutil": __import__("shutil"),
        "socket": __import__("socket"), "time": __import__("time"),
        "uuid": __import__("uuid"), "json": __import__("json"), "steps": [],
    }
    exec(code, context)
    return context


class DemotionCommandTests(unittest.TestCase):
    def test_program_parses_and_preserves_samba_command(self):
        tree = ast.parse(ops.DEMOTE_PROGRAM)
        self.assertTrue(tree)
        self.assertNotIn("--password=", ops.DEMOTE_PROGRAM)
        self.assertNotIn("--remove-other-dead-server", ops.DEMOTE_PROGRAM)
        self.assertIn("PASSWD_FD", ops.DEMOTE_PROGRAM)
        self.assertIn('["samba-tool", "domain", "demote", "-U" + admin]', ops.DEMOTE_PROGRAM)
        self.assertIn('if state == "dc":', ops.DEMOTE_PROGRAM)
        self.assertIn('if remote_account() != "member":', ops.DEMOTE_PROGRAM)
        self.assertIn('credential_run(["net", "ads", "join"', ops.DEMOTE_PROGRAM)
        self.assertIn('run(["net", "ads", "testjoin"])', ops.DEMOTE_PROGRAM)
        self.assertIn('stop_old_dc()', ops.DEMOTE_PROGRAM)

    def test_credentials_are_only_sent_over_inherited_fd(self):
        ctx = load_helpers()
        commands = []
        def fake_run(args, **kwargs):
            commands.append((args, kwargs))
            fd = int(kwargs["env"]["PASSWD_FD"])
            self.assertIn(fd, kwargs["pass_fds"])
            self.assertEqual(os.read(fd, 128), b"SensitiveSecret!\n")
            self.assertNotIn("SensitiveSecret!", " ".join(args))
            self.assertNotIn("PASSWD", kwargs["env"])
            return types.SimpleNamespace(returncode=0, stdout="OK", stderr="")
        with patch("subprocess.run", side_effect=fake_run):
            self.assertEqual(ctx["credential_run"](["net", "ads", "join"]), "OK")
        self.assertEqual(commands[0][0], ["net", "ads", "join"])

    def test_remote_account_distinguishes_dc_and_member(self):
        ctx = load_helpers()
        cases = [
            ("userAccountControl: 532480\nprimaryGroupID: 516\n", "dc"),
            ("userAccountControl: 4096\nprimaryGroupID: 515\n", "member"),
        ]
        for ldif, role in cases:
            ctx["credential_run"] = lambda args, data=ldif: data
            with self.subTest(role=role):
                self.assertEqual(ctx["remote_account"](), role)
        ctx["credential_run"] = lambda args: "userAccountControl: 0\nprimaryGroupID: 515\n"
        with self.assertRaisesRegex(RuntimeError, "não é DC nem membro"):
            ctx["remote_account"]()

    def test_member_validation_requires_member_services_before_demote(self):
        ctx = load_helpers()
        ctx["service_exists"] = lambda unit: unit in ("smb", "winbind")
        with patch("shutil.which", return_value="/usr/bin/tool"),\
             patch("pathlib.Path.is_file", return_value=True),\
             patch("pathlib.Path.is_symlink", return_value=False),\
             patch("pathlib.Path.read_text", return_value="nameserver 192.168.2.10\n"):
            ctx["validate_member_runtime"]()
        ctx["service_exists"] = lambda _: False
        with patch("shutil.which", return_value="/usr/bin/tool"):
            with self.assertRaisesRegex(RuntimeError, "Serviço de membro ausente"):
                ctx["validate_member_runtime"]()

    def test_live_samba_socket_is_skipped_but_databases_are_backed_up(self):
        import socket
        import tempfile
        ctx = load_helpers()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "private"
            destination = Path(temp) / "backup"
            source.mkdir()
            (source / "sam.ldb").write_bytes(b"test AD DB")
            (source / "secrets.ldb").write_bytes(b"test secrets DB")
            ipc = source / "msg.sock"
            ipc.mkdir()
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.bind(str(ipc / "1177"))
                ctx["copy_private_without_special"](source, destination)
                self.assertEqual((destination / "sam.ldb").read_bytes(), b"test AD DB")
                self.assertEqual((destination / "secrets.ldb").read_bytes(), b"test secrets DB")
                self.assertFalse((destination / "msg.sock" / "1177").exists())
            finally:
                endpoint.close()

    def test_no_implicit_reprovisioning_or_ad_database_deletion(self):
        source = ops.DEMOTE_PROGRAM
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("remove-other-dead-server", source)
        self.assertNotIn("domain provision", source)
        self.assertIn("backup_dir = create_backup()", source)
        self.assertIn('"primary_hostname": partner', source)
        self.assertIn("member-server.json", source)

if __name__ == "__main__":
    unittest.main()
