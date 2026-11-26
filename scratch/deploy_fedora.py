import paramiko
import os

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('66.163.123.90', username='euripedes', password='Btf1_Mk3', timeout=15)

sftp = ssh.open_sftp()

files_to_sync = [
    ('samba-ad-dc/ad_operations.py', '/home/euripedes/astral-ad-dns/samba-ad-dc/ad_operations.py'),
    ('samba-ad-dc/ad_operations.rs', '/home/euripedes/astral-ad-dns/samba-ad-dc/ad_operations.rs'),
    ('samba-ad-dc/provision_dc1.py', '/home/euripedes/astral-ad-dns/samba-ad-dc/provision_dc1.py'),
    ('web/src/App.jsx', '/home/euripedes/astral-ad-dns/web/src/App.jsx'),
]

for local_rel, remote_path in files_to_sync:
    local_path = os.path.join(r'z:\astral\astral-ad-dns', local_rel.replace('/', '\\'))
    print(f'Uploading {local_path} -> {remote_path}')
    sftp.put(local_path, remote_path)

sftp.close()
print('Upload complete.')

def run_remote(cmd, use_sudo=False):
    print(f'=== RUNNING: {cmd}')
    full_cmd = f'echo Btf1_Mk3 | sudo -S {cmd}' if use_sudo else cmd
    stdin, stdout, stderr = ssh.exec_command(full_cmd)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    if out:
        print(out)
    if err and 'password' not in err.lower():
        print('ERR:', err)

# 1. Rebuild web/dist
run_remote('cd /home/euripedes/astral-ad-dns/web && npm run build')

# 2. Rebuild cargo release
run_remote('cd /home/euripedes/astral-ad-dns && cargo build --release')

# 3. Restart astral-ad-dns service
run_remote('systemctl restart astral-ad-dns', use_sudo=True)

# 4. Check service status
run_remote('systemctl status astral-ad-dns --no-pager')

ssh.close()
