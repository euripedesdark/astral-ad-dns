"""Demotion uses the standard Samba command without exposing the password in ps."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"samba-ad-dc"))
import ad_operations as ops


class DemotionCommandTests(unittest.TestCase):
    def test_program_parses_and_has_no_extra_stop(self):
        ast.parse(ops.DEMOTE_PROGRAM)
        self.assertNotIn("systemctl", ops.DEMOTE_PROGRAM)
        self.assertNotIn("--password=", ops.DEMOTE_PROGRAM)
        self.assertNotIn("--server=", ops.DEMOTE_PROGRAM)
        self.assertIn("PASSWD_FD", ops.DEMOTE_PROGRAM)

    def test_only_standard_demote_command_is_executed_and_password_stays_out_of_argv(self):
        password="Secret-Test-Not-To-Log!"
        calls=[]
        def fake_run(args, **kwargs):
            calls.append((args,kwargs))
            if args[0]=="testparm":
                return types.SimpleNamespace(returncode=0,stdout="VMWARE\n",stderr="")
            if args[:3]==["samba-tool","fsmo","show"]:
                return types.SimpleNamespace(returncode=0,stdout="PdcEmulationMasterRole owner: CN=NTDS Settings,CN=DC-ERP,\n",stderr="")
            if args[:3]==["samba-tool","domain","demote"]:
                self.assertEqual(args,["samba-tool","domain","demote","-Uadministrator"])
                fd=int(kwargs["env"]["PASSWD_FD"])
                self.assertIn(fd,kwargs["pass_fds"])
                self.assertEqual(os.read(fd,128),password.encode()+bytes((10,)))
                self.assertNotIn(password," ".join(args))
                return types.SimpleNamespace(returncode=0,stdout="Demote successful",stderr="")
            raise AssertionError(args)

        request={"target_name":"VMWARE","admin_username":"administrator","admin_password":password}
        output=io.StringIO()
        with patch.object(sys,"stdin",io.StringIO(json.dumps(request))),\
             patch("subprocess.run",side_effect=fake_run),\
             contextlib.redirect_stdout(output):
            exec(compile(ops.DEMOTE_PROGRAM,"<demote>", "exec"),{"__name__":"__main__"})
        self.assertTrue(json.loads(output.getvalue())["success"])
        self.assertEqual(len(calls),3)

    def test_fsmo_ownership_blocks_before_demote(self):
        calls=[]
        def fake_run(args, **kwargs):
            calls.append(args)
            if args[0]=="testparm":
                return types.SimpleNamespace(returncode=0,stdout="VMWARE\n",stderr="")
            return types.SimpleNamespace(returncode=0,stdout="PdcEmulationMasterRole owner: CN=NTDS Settings,CN=VMWARE,\n",stderr="")
        output=io.StringIO()
        request={"target_name":"VMWARE","admin_username":"administrator","admin_password":"secret"}
        with patch.object(sys,"stdin",io.StringIO(json.dumps(request))),\
             patch("subprocess.run",side_effect=fake_run),\
             contextlib.redirect_stdout(output),\
             self.assertRaises(SystemExit):
            exec(compile(ops.DEMOTE_PROGRAM,"<demote>", "exec"),{"__name__":"__main__"})
        self.assertIn("FSMO",json.loads(output.getvalue())["error"])
        self.assertEqual(len(calls),2)

if __name__=="__main__":
    unittest.main()
