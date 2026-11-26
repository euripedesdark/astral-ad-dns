$sshDir = "C:\Users\euripedes\.ssh"
Copy-Item "Z:\.ssh\id_ed25519" "$sshDir\id_ed25519" -Force
Copy-Item "Z:\.ssh\id_ed25519.pub" "$sshDir\id_ed25519.pub" -Force
$keyPath = "$sshDir\id_ed25519"
& icacls.exe $keyPath /inheritance:r /grant:r "euripedes:F"
& ssh.exe -i $keyPath -o StrictHostKeyChecking=no -T git@github.com
