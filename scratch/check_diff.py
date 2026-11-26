import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('66.163.123.90', username='euripedes', password='Btf1_Mk3', timeout=10)

cmd = 'cd /home/euripedes/astral-ad-dns && git diff'
stdin, stdout, stderr = ssh.exec_command(cmd)
print('GIT DIFF ON FEDORA:')
print(stdout.read().decode('utf-8', errors='replace'))

ssh.close()
