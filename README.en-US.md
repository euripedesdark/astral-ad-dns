# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md"><b>🇺🇸 English (US)</b></a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Enterprise Rust Module with Web GUI for Administration, Provisioning, and Management of Samba 4 Active Directory (Functional Level 2016) and Hybrid BIND 9 DNS** — Developed based on the in-depth enterprise Linux Active Directory architecture technical guide by Euripedes Batista.

Distributed under the **GNU AGPL v3** license. See [`LICENSE.md`](LICENSE.md).

---

## 📋 Table of Contents
1. [Linux Host Preparation by Distribution](#1-linux-host-preparation-by-distribution)
2. [Automated Installation & Deployment (`deploy_ad_dns.py`)](#2-automated-installation--deployment-deploy_ad_dnspy)
3. [Alternative Manual Deployment (Cargo & Systemd)](#3-alternative-manual-deployment-cargo--systemd)
4. [Web Provisioning Wizard & Supported Topologies](#4-web-provisioning-wizard--supported-topologies)
5. [Public Key Infrastructure (Step-CA PKI & LDAPS)](#5-public-key-infrastructure-step-ca-pki--ldaps)
6. [Hybrid DNS Architecture with BIND 9 & SELinux](#6-hybrid-dns-architecture-with-bind-9--selinux)
7. [Clean Re-Deployment, Rejoining & Orphan AD Cleanup](#7-clean-re-deployment-rejoining--orphan-ad-cleanup)
8. [Operational Verification & Diagnostics](#8-operational-verification--diagnostics)
9. [Firewall Safety & Audit Trail](#9-firewall-safety--audit-trail)

---

## 1. Linux Host Preparation by Distribution

Before launching the web provisioning wizard to create or join a domain, prepare the required system packages and enterprise repositories:

### Fast Automated Preparation
The bundled `deploy_ad_dns.py` script includes a dedicated preparation switch that configures GPG-verified corporate repositories and installs all required binaries without modifying local Samba databases or requiring compilation:

```bash
# Configure repositories and install system packages without building the web panel
python3 deploy_ad_dns.py --prepare-ad-only
```

### Distribution Specifics

* **RHEL 10 / AlmaLinux 10 / Rocky Linux 10 (EL10):**
  - Imports official GPG key `RPM-GPG-KEY-TISSAMBA-10`.
  - Enables Tranquil IT Samba repository: `https://samba.tranquil.it/redhat10/samba-4.24/`.
  - Enables CRB (`dnf config-manager --set-enabled crb`) and EPEL 10.
  - Installs: `samba`, `samba-dc`, `samba-winbind`, `samba-winbind-clients`, `krb5-workstation`, `ldb-tools`, `bind`, `bind-utils`, `chrony`, `python3-setproctitle`, `policycoreutils-python-utils`.
* **RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (EL9):**
  - Imports key `RPM-GPG-KEY-TISSAMBA-9` and repository `https://samba.tranquil.it/redhat9/samba-4.24/`.
  - Enables CRB and EPEL 9.
* **Fedora 44 / 45:**
  - Uses native distribution packages (`dnf install -y samba samba-dc bind bind-utils chrony krb5-workstation`).
* **Arch Linux:**
  - Native installation via pacman: `pacman -S --needed samba bind chrony krb5`.
* **Debian 12 (Bookworm) / Ubuntu 24.04 LTS:**
  - Native installation via apt: `apt-get install -y samba winbind krb5-user bind9 bind9utils chrony ldb-tools`.

---

## 2. Automated Installation & Deployment (`deploy_ad_dns.py`)

The `deploy_ad_dns.py` script automates the complete operational lifecycle: high-performance release compilation of the Rust backend, production build of the Vite/React frontend, deployment to `/opt/astral-ad-dns/`, installation and activation of the systemd unit, and idempotent web firewall port configuration.

```bash
# Complete local build and deployment (skipping git push)
python3 deploy_ad_dns.py --skip-git

# Complete deployment with automated host AD package preparation
python3 deploy_ad_dns.py --prepare-ad --skip-git
```

### What Automated Deployment Executes:
1. **Backend Compilation**: Runs `cargo build --release --bin astral-ad-dns` producing an optimized binary.
2. **Frontend Production Build**: Runs `npm install` and `npm run build` in `web/`.
3. **Installation into `/opt/astral-ad-dns`**:
   - Binary copied to `/opt/astral-ad-dns/astral-ad-dns`.
   - Static web assets deployed to `/opt/astral-ad-dns/web/dist/`.
   - Automation helpers installed into `/opt/astral-ad-dns/samba-ad-dc/`.
   - System symlink generated at `/usr/local/bin/astral-ad-dns`.
4. **Systemd Service Setup**:
   - Generates `/etc/systemd/system/astral-ad-dns.service`.
   - Performs `systemctl daemon-reload`, enables and starts the service.
5. **Firewall Port Audit**:
   - Ensures TCP port 8095 is active in `iptables` without flushing active rules.
6. **Automatic Health Check**:
   - Tests local HTTP responsiveness on `http://127.0.0.1:8095/api/auth/providers`.

### Fast Updates on Secondary Nodes (DC2 / RODC)
To sync updated operational scripts to secondary nodes without recompiling the Rust binary:
```bash
cd ~/astral-ad-dns
git pull origin main
sudo cp -r samba-ad-dc/* /opt/astral-ad-dns/samba-ad-dc/
sudo systemctl restart astral-ad-dns.service
```

---

## 3. Alternative Manual Deployment (Cargo & Systemd)

If you prefer to perform compilation and system installation manually:

```bash
# 1. Compile Rust Backend
cargo build --release --bin astral-ad-dns

# 2. Build React / Vite Frontend
cd web
npm install
npm run build
cd ..

# 3. Create System Structure
sudo mkdir -p /opt/astral-ad-dns/web
sudo cp target/release/astral-ad-dns /opt/astral-ad-dns/
sudo cp -r web/dist /opt/astral-ad-dns/web/
sudo cp -r samba-ad-dc /opt/astral-ad-dns/
sudo ln -sf /opt/astral-ad-dns/astral-ad-dns /usr/local/bin/astral-ad-dns

# 4. Install and Start Systemd Unit
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service

# 5. Access in Web Browser
# Navigate to http://<SERVER_IP>:8095
```

---

## 4. Web Provisioning Wizard & Supported Topologies

Open `http://<SERVER_IP>:8095` in your browser and click on **"Provisioning Wizard"**. The platform natively supports four core Active Directory topologies:

### 1. Primary Domain Controller (DC1 - New Domain)
* Creates a fresh Active Directory forest at **2016** functional level.
* Generates Kerberos realm, NetBIOS domain, Global Catalog, and internal DNS backend (`SAMBA_INTERNAL`).
* Optionally provisions an integrated Step-CA server for enterprise LDAPS certificates.

### 2. Secondary Domain Controller (DC2 - Read-Write Replica)
* Joins the host as an additional full Domain Controller in the existing forest.
* Multi-Master bidirectional directory replication via DRS (Directory Replication Services).
* Automated SYSVOL replication and synchronization from partner with NT ACL preservation.
* Strict signed NTP synchronization for Kerberos (`ntp_signd`).

### 3. Read-Only Domain Controller (RODC)
* Ideal for branch offices, retail locations, or edge environments with lower physical security.
* Local LDB directory database is read-only; user passwords are not cached by default.
* Partner-side DRS validation preventing privileged RPC calls that could impact MIT KDC.

### 4. Domain Member Server (MEMBER)
* Integrates Linux machines into Active Directory for unified enterprise authentication (Winbind / PAM / NSS).
* Does not host directory database partitions (`sam.ldb`) or consume DC replication resources.

---

## 5. Public Key Infrastructure (Step-CA PKI & LDAPS)

Astral AD provides enterprise-grade TLS certificate enrollment and validation:

* **Two-Tier Certificate Hierarchy**:
  $$\text{Root CA} \longrightarrow \text{Intermediate CA} \longrightarrow \text{Domain Controller Certificate}$$
* **Full-Chain Trust Validation on Domain Join**:
  - Secondary nodes (DC2 / RODC) automatically retrieve the official intermediate signing certificate via HTTPS (`https://<CA_IP>:9444/intermediates.pem`).
  - OpenSSL validates the complete trust chain (`-CAfile trusted-step-root.crt -untrusted intermediates.pem dc.crt`) avoiding local issuer lookup errors.
  - Samba's `tls cafile` is automatically populated with the concatenated full chain.
* **Automated Certificate Renewal**:
  - Configures the `astral-ad-tls-renew.timer` systemd timer to audit and renew certificates every 15 minutes with zero downtime.

---

## 6. Hybrid DNS Architecture with BIND 9 & SELinux

The platform solves DNS conflicts between internal AD directory records and external recursive internet lookups:

* **Port 53 (UDP/TCP)**: Dedicated to `SAMBA_INTERNAL` on the Samba AD DC, authoritative for domain records and `_msdcs` locators.
* **Port 5353 (UDP/TCP)**: Isolated local **BIND 9** instance configured exclusively as a recursive resolver bound to `127.0.0.1:5353`.
* **SELinux Policy Integration**:
  - The wizard checks existing port reservations using `semanage port -l`.
  - Safely labels port 5353 with `dns_port_t` even when concurrent policies (such as `howl_port_t`) coexist, keeping SELinux in `Enforcing` mode without compromises.

---

## 7. Clean Re-Deployment, Rejoining & Orphan AD Cleanup

When repurposing existing machines or cleaning up after retired test environments:

* **Orphan Database Cleanup**:
  - When clean deployment (`clean_existing`, `rejoin`, or `overwrite_existing`) is enabled, the wizard safely expurges orphan directory databases from prior domains (e.g., test setups like `ASTRAL.CELESTE`).
  - Automatically deactivates, stops, and removes any leftover legacy Step-CA services belonging to previous domains.
* **Automatic Rollback Snapshot**:
  - Prior to any destructive file removal, an automated cryptographic backup is created under `/var/backups/astral-ad-dns/provision/<ID>/` containing previous configurations, firewall rules, and rollback manifests.
* **Safe Server Demotion**:
  - If the server identity is registered in the partner DC, executes `samba-tool domain demote --remove-other-dead-server` to keep directory topology clean.

---

## 8. Operational Verification & Diagnostics

Validate domain and directory health directly from the web console (**Checklist** and **Diagnostics** tabs) or via the Linux terminal:

```bash
# 1. Inspect DRS replication status with partner DC
sudo samba-tool drs showrepl

# 2. Check structural integrity across all directory partitions
sudo samba-tool dbcheck --cross-ncs

# 3. Validate Samba configuration syntax
testparm -s

# 4. Query DNS SRV service locators
dig @127.0.0.1 _ldap._tcp.dc._msdcs.<DOMAIN> SRV +short

# 5. Verify NTP clock synchronization for Kerberos
chronyc tracking

# 6. Verify LDAPS TLS handshake and certificate chain
openssl s_client -connect 127.0.0.1:636 -showcerts < /dev/null
```

---

## 9. Firewall Safety & Audit Trail

* **Anti-Destruction Safety Locks (`/api/firewall`)**:
  - The Rust engine strictly rejects destructive commands containing `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R`, or `nft flush`.
  - Idempotent rule insertion via `iptables -I INPUT 1` targeting only missing ports.
* **Thread-Safe In-Memory Audit Trail (`/api/audit`)**:
  - Circular buffer storing up to 500 events with timestamps, operators, action types, execution modes, and correlation IDs.
  - Strict credential redacting in all system logs and audit entries.

---

## 📄 License

This project is free software licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0`). See [`LICENSE.md`](LICENSE.md) for full license details.
