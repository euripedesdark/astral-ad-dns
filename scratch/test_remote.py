import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('66.163.123.90', username='euripedes', password='Btf1_Mk3', timeout=10)

commands = [
    'cd /home/euripedes/astral-ad-dns && git status',
    'python3 -c "import sys; sys.path.insert(0, \'/home/euripedes/astral-ad-dns/samba-ad-dc\'); from ad_operations import configure_bind, detect_distro_profile; print(detect_distro_profile())"'
]

for cmd in commands:
    print('=== CMD:', cmd)
    stdin, stdout, stderr = ssh.exec_command(f'echo Btf1_Mk3 | sudo -S {cmd}' if 'sudo' in cmd else cmd)
    print(stdout.read().decode('utf-8', errors='replace'))
    err = stderr.read().decode('utf-8', errors='replace')
    if err and 'password' not in err.lower():
        print('ERR:', err)

ssh.close()
