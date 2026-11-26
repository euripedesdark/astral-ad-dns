import subprocess

patch_data = """From 6faaf29ebf20c3e4286e704d91c3949a4f57ef63 Mon Sep 17 00:00:00 2001
From: euripedesdark <euripedesdark@gmail.com>
Date: Wed, 25 Nov 2026 17:37:47 -0300
Subject: [PATCH] fix(bind-provision): stop/mask avahi-daemon across all
 distros to free UDP 5353 and set domain_role in new-dc payload

---
 samba-ad-dc/ad_operations.py | 5 +++--
 samba-ad-dc/ad_operations.rs | 4 ++++
 samba-ad-dc/host_prep.rs     | 4 ++++
 samba-ad-dc/provision_dc1.py | 5 +++--
 web/src/App.jsx              | 1 +
 5 files changed, 15 insertions(+), 4 deletions(-)

diff --git a/samba-ad-dc/ad_operations.py b/samba-ad-dc/ad_operations.py
index 396e886..b667339 100644
--- a/samba-ad-dc/ad_operations.py
+++ b/samba-ad-dc/ad_operations.py
@@ -710,12 +710,13 @@ def configure_bind(request, root=Path('/'), run=checked_run):
     apparmor_steps = []
     try:
         configure_distro_bind_environment(root, profile, port, run)
-        if profile.family == 'debian' and root == Path('/'):
+        if root == Path('/'):
             try:
+                run(['systemctl', 'mask', '--now', 'avahi-daemon.service', 'avahi-daemon.socket'])
                 run(['systemctl', 'stop', 'avahi-daemon.service', 'avahi-daemon.socket'])
-                run(['systemctl', 'mask', 'avahi-daemon.service', 'avahi-daemon.socket'])
             except (OperationError, FileNotFoundError):
                 pass
+        if profile.family == 'debian' and root == Path('/'):
             rndc_key = root / 'etc/bind/rndc.key'
             if rndc_key.is_file():
                 try:
diff --git a/samba-ad-dc/ad_operations.rs b/samba-ad-dc/ad_operations.rs
index 8d5d1e1..6858341 100644
--- a/samba-ad-dc/ad_operations.rs
+++ b/samba-ad-dc/ad_operations.rs
@@ -212,6 +212,10 @@ pub fn configure_bind(request: &Value, root: &Path) -> Result<Vec<String>, Strin
         .unwrap_or(5353);
 
     // 1. Prepare directory permissions and distro environment
+    if root == Path::new("/") {
+        let _ = Command::new("systemctl").args(["mask", "--now", "avahi-daemon.service", "avahi-daemon.socket"]).output();
+        let _ = Command::new("systemctl").args(["stop", "avahi-daemon.service", "avahi-daemon.socket"]).output();
+    }
     let bind_dir = root.join(profile.bind_work_dir.trim_start_matches('/'));
     fs::create_dir_all(&bind_dir).map_err(|e| e.to_string())?;
     let _ = Command::new("chown").args(["-R", &format!("{}:{}", profile.bind_user, profile.bind_group), bind_dir.to_str().unwrap()]).output();
diff --git a/samba-ad-dc/host_prep.rs b/samba-ad-dc/host_prep.rs
index 8bb57e5..0cd0db6 100644
--- a/samba-ad-dc/host_prep.rs
+++ b/samba-ad-dc/host_prep.rs
@@ -152,6 +152,10 @@ pub fn prepare_host_packages(root: &Path) -> Result<String, String> {
             return Err(format!("dnf install falhou: {}", String::from_utf8_lossy(&install_res.stderr)));
         }
 
+        // Mask avahi-daemon to prevent conflict on port 5353
+        let _ = Command::new("systemctl").args(["mask", "--now", "avahi-daemon.service", "avahi-daemon.socket"]).output();
+        let _ = Command::new("systemctl").args(["stop", "avahi-daemon.service", "avahi-daemon.socket"]).output();
+
         let msg = format!("Enterprise Linux {} preparado com sucesso com Tranquil IT.", major);
         println!("[OK] {}", msg);
         return Ok(msg);
diff --git a/samba-ad-dc/provision_dc1.py b/samba-ad-dc/provision_dc1.py
index 70717bd..036872e 100644
--- a/samba-ad-dc/provision_dc1.py
+++ b/samba-ad-dc/provision_dc1.py
@@ -684,12 +684,13 @@ def configure_bind(request, root=Path('/'), run=checked_run):
     apparmor_steps = []
     try:
         configure_distro_bind_environment(root, profile, 5353, run)
-        if profile.family == 'debian' and root == Path('/'):
+        if root == Path('/'):
             try:
+                run(['systemctl', 'mask', '--now', 'avahi-daemon.service', 'avahi-daemon.socket'])
                 run(['systemctl', 'stop', 'avahi-daemon.service', 'avahi-daemon.socket'])
-                run(['systemctl', 'mask', 'avahi-daemon.service', 'avahi-daemon.socket'])
             except (OperationError, FileNotFoundError):
                 pass
+        if profile.family == 'debian' and root == Path('/'):
             rndc_key = root / 'etc/bind/rndc.key'
             if rndc_key.is_file():
                 try:
diff --git a/web/src/App.jsx b/web/src/App.jsx
index 49652d4..3fd21c6 100644
--- a/web/src/App.jsx
+++ b/web/src/App.jsx
@@ -3964,6 +3964,7 @@ function WizardModal({ onClose, t, showToast }) {
       const endpoint = mode === 'new' ? '/api/provision/new-dc' : '/api/provision/join-dc';
       const domainRole = mode === 'join_rodc' ? 'RODC' : mode === 'join_member' ? 'MEMBER' : 'DC';
       const payload = mode === 'new' ? {
+        domain_role: 'DC',
         netbios_name: mode === 'new' ? primaryHostname.trim().split('.')[0].toUpperCase() : dcNetbiosName,
         upstream_forwarders: upstreams,
         global_catalog: globalCatalog,
-- 
2.56.0.vfs.0.4
"""

proc = subprocess.Popen(
    [
        "plink", "-batch", "-hostkey", "SHA256:izBrNjyp4wHCTJaqbi3Y/0uQ+q/iGc+zyPZMP2mODiA",
        "-pw", "Btf1_Mk3", "euripedes@66.163.123.90",
        "cat > /tmp/fix_bind_avahi.patch && cd /home/euripedes/astral-ad-dns && git apply /tmp/fix_bind_avahi.patch && git status"
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
stdout, stderr = proc.communicate(input=patch_data)
print("STDOUT:", stdout)
print("STDERR:", stderr)
print("RC:", proc.returncode)
