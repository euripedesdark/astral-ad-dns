# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md"><b>🇺🇸 English (US)</b></a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Enterprise Rust Module with Web GUI for Administration and Provisioning of Samba 4 Active Directory 2016 and Hybrid BIND 9** — Full platform developed based on the in-depth enterprise Linux Active Directory architecture guide by Euripedes Batista.

Licensed under **GNU AGPL v3**. See [`LICENSE.md`](LICENSE.md).

---

## 🚀 What's New in Version 1.5.0

### 1. Operational Dashboard & Health Status Indicator
- **Global Health Status**: Unequivocal and standardized health badge (`operational`, `degraded`, `unavailable`, `unknown`) displayed in the header and returned by `/api/status`.
- **Interactive Operational Validation Checklist (`/api/checks`)**: Real-time automated test suite measuring latency in milliseconds for:
  - `testparm -s` (Configuration syntax validation).
  - `samba-tool dbcheck --cross-ncs` (Integrity analysis across 3,900+ LDB directory objects).
  - `chronyc tracking` (Clock synchronization, stratum, and offset for Kerberos tickets).
  - `klist` (Local Kerberos ticket verification).
  - DNS SRV Locators (`_ldap._tcp`, `_kerberos._tcp`, `_kerberos._udp`, `_kpasswd._udp`).

### 2. Deep Infrastructure & Dependency Diagnostics (`/api/diagnostics`)
Dedicated UI tab with continuous scanning, latency measurements, root causes, and actionable recommendations for 10 core subsystems:
- **REST Engine & Web Console**: Immediate Axum/Tokio runtime responsiveness.
- **Samba Active Directory Service**: Systemd service status and daemon health.
- **Authentication Protocols**: Listening sockets for LDAP (TCP 389) and Kerberos (TCP 88).
- **BIND 9 Hybrid DNS**: Isolated recursive resolution on `127.0.0.1:5353`.
- **SRV Record Resolution**: Local DNS resolution verification via `127.0.0.1`.
- **Chrony NTP Time Synchronization**: Time consistency and signed NTP socket (`/var/lib/samba/ntp_signd`).
- **Operating System Dependencies**: Essential binary availability (`samba-tool`, `named`, `chronyc`, `iptables`, `host`, `klist`).
- **Filesystem & SAM LDB**: Critical file permissions and presence (`smb.conf`, `sam.ldb`, `krb5.conf`).
- **SELinux Security Policies**: Operating mode check (`Enforcing` / `Permissive` / `Disabled`).
- **Database Consistency**: Directory structure consistency and replication status.

### 3. Safe Firewall Port Management (`/api/firewall`)
- **Strict Non-Destructive Guarantee**: Token-based backend validator rejecting any command containing `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R`, or `nft flush`.
- **Port Audit**: Continuous inspection of the 19 standard Active Directory and BIND 9 ports via `iptables -C INPUT`.
- **Safe Insertion**: Rules inserted exclusively with `iptables -I INPUT 1`, with native simulation (`dry_run`) support.

### 4. In-Memory Circular Audit Trail (`/api/audit`)
- Thread-safe circular buffer (up to 500 events) storing correlation IDs (`evt_...`), operators, action types, targets, execution mode, status, and details.
- Interactive filtering in the web console by mode (All / Simulations Only / Real Executions Only) and search queries.

### 5. Preventive Simulation (`dry_run`) & Strict Pre-validation
- Full dry-run support across Domain Provisioning (`/api/provision`), Users (`/api/users`), Groups (`/api/groups`), Computers (`/api/computers`), DNS (`/api/dns`), and BIND 9 (`/api/bind`).
- **Anti-Deletion Locks**: Accidental deletion prevention for Domain Controllers (`DC-ERP`) and core security groups ("Domain Admins", "Enterprise Admins", etc.).
- **Credential Masking**: Automated redacting of sensitive flags (`--adminpass=`, `--password=`, `-W`) from all logs.

### 6. Modern Web UI & Language Dropdown Selector
- Dropdown selection box (`<select>`) in the top navigation header for switching between 4 languages with `localStorage` persistence:
  - 🇧🇷 Português (Brasil)
  - 🇺🇸 English (US)
  - 🇪🇸 Español (España)
  - 🇫🇷 Français (France)
- 100% of interface labels, tooltips, dialogs, and alerts translated across all 4 languages.

### 7. Unified Access Policy & Multi-Provider Authentication
Implementation of the enterprise unified authentication & authorization policy:
- **Samba Active Directory / OAuth2**: Authentication for domain users and administrators with automatic LDAP/Kerberos group mapping or via SSO tokens issued by `astral-auth-service`.
- **Linux Local (Root / Sudo)**: Operating system administrator login for members of `wheel`/`sudo` groups or the `root` superuser.
- **PostgreSQL Superuser**: Direct database credential validation for any PostgreSQL user with `rolsuper = true` (e.g., `postgres`).
- **Bearer Token & Session Cookies**: Simultaneous validation of `Authorization: Bearer <jwt>` headers and `sso_token` / `astral_token` HTTP session cookies.
- **Dedicated Auth Endpoints**:
  - `POST /api/auth/login`: Credential validation and JWT session token generation.
  - `GET /api/auth/me`: Active operator identity and privilege inspection.
  - `POST /api/auth/logout`: Session termination and cookie invalidation.
  - `GET /api/auth/providers`: Supported authentication mechanisms catalog.
- **Preserved Scopes**: Applied across infrastructure modules while maintaining independence for `astral-saas-erp` (legacy Java auth) and `auth-service` web IAM.

---

## 🛠️ Build and Deployment

### Backend Compilation (Rust)
```bash
cargo build --release --bin astral-ad-dns
```

### Frontend Compilation (React Web GUI)
```bash
cd web
npm install
npm run build
cd ..
```

### Systemd Service Management
```bash
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service
```

Access in browser: `http://<YOUR_IP>:8095/` (or via reverse proxy on `/ad/` path).

---

## 📄 License & Contributing

- License: **GNU Affero General Public License v3.0** ([`LICENSE.md`](LICENSE.md))
- Contribution Guidelines: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security Policy: [`SECURITY.md`](SECURITY.md)
- Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)


### 7. Linux Wheel Privilege Verification for AD & BIND Operators
- **Wheel Group Compliance Check**: `has_wheel: bool` attribute added to `UserItem` (`/api/users`) and `AuthenticatedOperator` (`/api/auth/*`), validating whether Samba AD administrators and BIND operators hold permissions in the Linux host `wheel` group (`getent group wheel`).
- **Integration with `auth-service`**: Cross-validation with `LinuxPrivilegeService` ensuring corporate admins (`Administrator`, `Domain Admins`) are synchronized with the host OS while PostgreSQL superusers remain strictly isolated from OS privileges.