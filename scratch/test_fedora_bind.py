import sys, subprocess, tempfile
from pathlib import Path
sys.path.insert(0, '/home/euripedes/astral/astral-ad-dns/samba-ad-dc')
import ad_operations

p = ad_operations.detect_distro_profile()
orig = Path('/etc/named.conf').read_text()
cand = ad_operations.replace_options(orig, ad_operations.hybrid_options(['8.8.8.8', '1.1.1.1'], p.bind_work_dir, 5353))

with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
    f.write(cand)
    tname = f.name

print("Candidate written to", tname)
res = subprocess.run(['named-checkconf', tname], capture_output=True, text=True)
print("named-checkconf returncode:", res.returncode)
print("named-checkconf stdout:", res.stdout)
print("named-checkconf stderr:", res.stderr)

print("\n--- Testing choose_bind_port ---")
try:
    port = ad_operations.choose_bind_port(Path('/'), ad_operations.checked_run)
    print("Port chosen:", port)
except Exception as e:
    print("choose_bind_port FAILED:", e)

print("\n--- Testing check_bind_runtime ---")
try:
    ad_operations.check_bind_runtime(Path('/'), Path('/etc/named.conf'), 'named', ad_operations.checked_run, 5353)
    print("check_bind_runtime OK")
except Exception as e:
    print("check_bind_runtime FAILED:", e)

print("\n--- Testing prepare_bind_selinux ---")
try:
    undo = []
    steps = ad_operations.prepare_bind_selinux(Path('/'), ad_operations.checked_run, undo, 5353)
    print("prepare_bind_selinux steps:", steps)
except Exception as e:
    print("prepare_bind_selinux FAILED:", e)
