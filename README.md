# Astral AD & Hybrid DNS

<p align="center">
  <img src="web/public/astral-logo.svg" alt="Astral AD & Hybrid DNS" width="120" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <b>Enterprise Samba 4 Active Directory (2016 Functional Level) & Hybrid BIND 9 DNS Management Platform</b><br/>
  <i>Developed in Rust (Axum/Tokio) & React 18 / Tailwind CSS & Python 3 Engine</i>
</p>

<p align="center">
  <a href="#-language-selection--seleção-de-idioma"><b>🌐 Choose your Language / Escolha seu Idioma</b></a>
</p>

<p align="center">
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg" alt="License"/></a>
  <img src="https://img.shields.io/badge/Rust-1.80%2B-orange.svg" alt="Rust"/>
  <img src="https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg" alt="Samba 4 AD DC"/>
  <img src="https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg" alt="BIND 9"/>
  <img src="https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg" alt="Web GUI"/>
</p>

---

## 🌐 Language Selection / Seleção de Idioma

Select your preferred language below to read the **complete documentation**, including **step-by-step installation**, **production deployment guides**, **supported distributions**, **Active Directory topologies** (DC1, DC2 Replica RW, RODC, Member), **Step-CA PKI**, **Hybrid BIND 9 DNS**, and **troubleshooting**:

| Language | Document | Description |
| :--- | :--- | :--- |
| 🇧🇷 **Português (Brasil)** | [**`README.pt-BR.md`**](README.pt-BR.md) | Guia completo de implantação, topologias AD, preparação de pacotes, deploy automatizado e manual, PKI Step-CA e BIND 9. |
| 🇺🇸 **English (US)** | [**`README.en-US.md`**](README.en-US.md) | Full deployment guide, AD topologies (DC1, DC2, RODC, Member), automated/manual deploy, Step-CA PKI, and BIND 9. |
| 🇪🇸 **Español (España)** | [**`README.es-ES.md`**](README.es-ES.md) | Guía completa de despliegue, topologías AD, preparación de paquetes, despliegue automatizado y manual, PKI Step-CA y BIND 9. |
| 🇫🇷 **Français (France)** | [**`README.fr-FR.md`**](README.fr-FR.md) | Guide complet de déploiement, topologies AD, préparation des paquets, déploiement automatisé et manuel, PKI Step-CA et BIND 9. |

---

## 🚀 Overview & Key Capabilities

**Astral AD & Hybrid DNS** is a high-performance enterprise management and provisioning platform designed for Linux environments (RHEL / AlmaLinux / Rocky Linux 9 & 10, Fedora 44/45, Arch Linux, Debian, and Ubuntu).

### Core Features:
- **Active Directory Provisioning & Joining Wizard (`/api/provision`)**:
  - **Primary Domain Controller (DC1)**: New Active Directory Forest at functional level 2016.
  - **Secondary Domain Controller (DC2 Replica RW)**: Bidirectional Multi-Master replication and DRS synchronization.
  - **Read-Only Domain Controller (RODC)**: Delegated branch office controller with read-only database replication.
  - **Domain Member Server (MEMBER)**: Seamless authentication node without hosting local directory databases.
  - **Clean Re-deployment & Orphan AD Protection**: Automatic backup, rollback, and safe demotion/cleanup of legacy foreign domains.
- **Enterprise PKI & Step-CA Integration**:
  - Full-chain certificate validation (**Root CA** $\rightarrow$ **Intermediate CA** $\rightarrow$ **DC Certificate**).
  - Automated LDAPS configuration for Samba AD with scheduled background renewal.
- **Hybrid BIND 9 Recursive Engine**:
  - Independent recursion on `127.0.0.1:5353` forwarding to external DNS, keeping port 53 exclusively for Samba AD internal DNS (`_msdcs`).
  - Native SELinux policy management (`dns_port_t`).
- **Operational Health Dashboard & Interactive Checklist**:
  - Millisecond latency validation for `testparm`, `samba-tool dbcheck`, `chronyc tracking`, Kerberos tickets, and SRV locators.
- **Strict Non-Destructive Firewall Management (`/api/firewall`)**:
  - Automated inspection and safe insertion of all 19 standard AD ports without flushing active rules.
- **Thread-Safe In-Memory Audit Trail & Simulation (`dry_run`)**:
  - Correlation tracking for all administrative actions with credential masking.

---

## 📦 Quick Deployment Summary

For full distribution prerequisites and configuration details, refer to your language file above.

### ⚠️ Running Without Git Credentials (`--skip-git`)
By default, always use the `--skip-git` flag when deploying on servers to ensure the script executes purely local operations without requesting Git credentials or attempting a remote push:

```bash
# 1. Prepare distribution packages (Debian 12/13, EL10, EL9)
# Fedora, openSUSE / SLES, Arch Linux, and Ubuntu use their official distribution repositories directly
python3 deploy_ad_dns.py --prepare-ad-only

# 2. Automated complete build, installation to /opt/astral-ad-dns and systemd startup (WITHOUT Git push)
python3 deploy_ad_dns.py --skip-git

# Or combine both package preparation and local deployment in one step:
python3 deploy_ad_dns.py --prepare-ad --skip-git

# 3. Access the Web Management Wizard
# Open http://<SERVER-IP>:8095 in your browser
```

> **FAQ — Does the Web Wizard install Samba packages automatically?**
> - **Fedora, openSUSE / SUSE, Arch Linux, and Ubuntu**: **YES**. They use their official distribution packages directly (no third-party repository required). Missing packages are installed using the native package manager (`dnf`, `zypper`, `pacman`, `apt`). On Ubuntu 24.04 LTS, packages match Debian package names natively (`samba-ad-dc`, `krb5-user`, etc.) without Tranquil IT.
> - **Debian (12/13) and Enterprise Linux (RHEL, AlmaLinux, Rocky Linux EL9/EL10)**: These distributions require the Tranquil IT Samba Active Directory packages (`samba-ad-dc` / `samba-dc`) compiled specifically for Domain Controller operations. Run `python3 deploy_ad_dns.py --prepare-ad-only` first to configure the official Tranquil IT GPG repository (and CRB/EPEL on EL). Once added, the web wizard can install and manage packages seamlessly.

---

## 📄 License

Licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0`). See [`LICENSE.md`](LICENSE.md) for full terms.
