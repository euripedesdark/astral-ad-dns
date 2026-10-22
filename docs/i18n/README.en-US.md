# Astral AD & Hybrid DNS

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Samba](https://img.shields.io/badge/Samba-4-green.svg)
![Kerberos](https://img.shields.io/badge/Auth-Kerberos%20%2F%20LDAPS-orange.svg)
![DNS](https://img.shields.io/badge/DNS-Contextual%20Resolver-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)

**Enterprise Samba 4 Active Directory Domain Controller & Hybrid DNS Engine** — Specialized module of the Astral ecosystem providing Active Directory Domain Controller (AD DC) services, centralized identity/authentication (LDAPS/Kerberos), and intelligent DNS resolution with contextual upstream selection.

This project is licensed under **GNU AGPL v3**. See [`LICENSE.md`](LICENSE.md).

---

## 🎯 Key Features

- **Samba 4 Active Directory Domain Controller (AD DC)**:
  - Multi-distribution automated provisioning scripts (Fedora/RHEL, Debian 13 Trixie, and Arch Linux).
  - Out-of-the-box secure provisioning with automatic SSL/TLS certificates (Step-CA) and LDAPS on port 636.
  - Native compatibility with Windows clients (Group Policy Objects, RSAT) and Linux endpoints integrated via SSSD/PAM.
  - Standardized provisioning secrets managed securely through isolated `auth.env`.
- **Context-Aware Hybrid DNS Resolver**:
  - Offline classification and selection of trustworthy global DNS providers (DNSSEC = true, reliability >= 0.95).
  - Built-in integration with Pi-hole and dnsmasq for telemetry and advertisement ad-blocking.
  - Local database containing more than 8 MB of worldwide DNS servers (`nameservers.csv`), ensuring data sovereignty.
- **Zero Vendor Lock-in**:
  - Full Microsoft Active Directory emulation without client access licensing (CAL) fees.
  - Native integration with `astral-auth-service`, `astral-internet-security`, and `astral-traffic-guard`.

---

## 🏗️ Project Structure

```
astral-ad-dns/
├── README.md                                 # Multilingual documentation hub
├── README.pt-BR.md                           # Documentation in Portuguese
├── README.en-US.md                           # Documentation in English
├── README.es-ES.md                           # Documentation in Spanish
├── README.fr-FR.md                           # Documentation in French
├── LICENSE.md                                # GNU AGPLv3 License
├── DONATE.md                                 # Donations and sponsorship guide
├── samba-ad-dc/                              # AD DC Automation and Provisioning
│   ├── auth.env.example                      # Template for secrets (REALM, HOSTNAME, SENHA_ADMIN)
│   ├── fedoradc-SSL.py                       # Provisioner for Fedora / RHEL with SSL
│   ├── fedora42dc.py                         # Standard provisioner for Fedora / RHEL
│   ├── debian13-dc-ssl.py                    # Provisioner for Debian 13 with SSL and AppArmor
│   ├── debian13-dc-no-ssl.py                 # Standard provisioner for Debian 13
│   ├── arch-DC-SSL.py                        # Provisioner for Arch Linux with SSL
│   └── arch42dc-no-ssl.py                    # Standard provisioner for Arch Linux
└── dns/                                      # DNS Resolution & Upstreams
    ├── nameservers.csv                       # Curated trustworthy global DNS database (>8MB)
    └── pihole.py                             # Blocklist and Pi-hole integration engine
```

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Directory Service** | Samba 4 AD DC | Full Active Directory emulation, LDAP, Kerberos KDC |
| **Cryptography & Identity** | OpenSSL / Step-CA | Automated PKI, LDAPS (TCP 636), X.509 certificates |
| **DNS Resolution** | BIND9 DLZ / dnsmasq / Pi-hole | Domain authoritative DNS and contextual ad/telemetry filtering |
| **Automation Engine** | Python 3.12+ | Zero-touch OS orchestration and host provisioning |
| **Operating Systems** | Linux (Fedora 42, Debian 13, Arch) | Enterprise-grade, auditable host operating systems |

---

## 🚀 Getting Started

1. Configure domain settings in `samba-ad-dc/auth.env`:
   ```bash
   cp samba-ad-dc/auth.env.example samba-ad-dc/auth.env
   chmod 600 samba-ad-dc/auth.env
   nano samba-ad-dc/auth.env
   ```
2. Run the automated provisioner for your Linux distribution:
   ```bash
   # For Fedora / RHEL with LDAPS and SSL:
   sudo python3 samba-ad-dc/fedoradc-SSL.py

   # For Debian 13 with LDAPS and SSL:
   sudo python3 samba-ad-dc/debian13-dc-ssl.py
   ```
3. Test Kerberos authentication and DNS resolution:
   ```bash
   kinit administrator
   klist
   smbclient -L localhost -U%
   ```

---

## 💖 Support the Project

Astral AD & Hybrid DNS is open-source software maintained by an independent engineer.

If this project has saved you or your team time and infrastructure costs, please consider supporting development:

### International Transfer (Wise)

| | |
|---|---|
| **Beneficiary** | Euripedes Batista de Paiva Junior |
| **Account Type** | Checking |
| **Routing number (Wire & ACH)** | `101019628` |
| **Account number** | `215822927677` |
| **Bank Name** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT / BIC** | `TRWIUS35XXX` |

### Brazil (PIX)

```text
24adc62c-b073-4587-974d-03fe35f6733f
```

---

## 📄 License

This project is licensed under **GNU Affero General Public License v3.0 (AGPLv3)**. See [`LICENSE.md`](LICENSE.md).

(c) 2026 Astral AD & Hybrid DNS — **Created by: Euripedes Batista de Paiva Junior**
