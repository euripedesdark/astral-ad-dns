import sys, traceback
from pathlib import Path
sys.path.insert(0, '/home/euripedes/astral/astral-ad-dns/samba-ad-dc')
import ad_operations

try:
    print("Calling configure_bind with forwarders=['8.8.8.8']...")
    steps = ad_operations.configure_bind({'forwarders': ['8.8.8.8']}, Path('/'), ad_operations.checked_run)
    print("SUCCESS! Steps:")
    for s in steps:
        print("  -", s)
except Exception as e:
    print("FAILED with Exception:", type(e).__name__, e)
    traceback.print_exc()
