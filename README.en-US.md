# Astral AD & Hybrid DNS

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%20%2B%20Tailwind-blueviolet.svg)

**Enterprise Rust Module with Web GUI for Administration and Provisioning of Samba 4 Active Directory 2016 and Hybrid BIND 9** — Full platform developed based on the in-depth enterprise Linux Active Directory architecture guide by Euripedes Batista.

Licensed under **GNU AGPL v3**. See [`LICENSE.md`](LICENSE.md).

---

## 🚀 Features (v1.4.0)

- **Rust Backend Engine (Axum 0.8 + Tokio)**:
  - High performance REST API and static asset server listening on `0.0.0.0:8095`.
  - Native systemd service: `astral-ad-dns.service`.
  - **Firewall Safety Guarantee**: Existing firewall rules are NEVER flushed or cleared. All required ports are inspected (`iptables -C`) and appended non-destructively (`iptables -A`).
- **Modern Web Single Page Application (React 18 + TailwindCSS)**:
  - Enterprise dark theme UI with multilingual support: 🇧🇷 PT-BR, 🇺🇸 EN-US, 🇪🇸 ES-ES, 🇫🇷 FR-FR.
- **Active Directory Dashboard**:
  - Forest and Domain Functional Levels (Windows Server 2016).
  - Real-time status for Samba DC, BIND 9 hybrid forwarder (5353), and Chrony signed NTP.
  - Three-way DNS latency benchmark tool (Samba 53 vs BIND 5353 vs 8.8.8.8).
- **Users and Groups Management**:
  - Create, reset password, enable/disable, and delete Active Directory users and security groups.
- **DNS Zone & Record Management with Auto Reverse PTR**:
  - Authoritative forward and reverse (`in-addr.arpa`) zone administration.
  - **Automatic Reverse PTR Generation**: Automatically discovers reverse subnets and creates reverse PTR records upon adding A records.
- **Hybrid BIND 9 Controller**:
  - Dynamic upstream forwarders editor with `named-checkconf` syntax validation and zero-downtime reloads.
  - Live query log stream viewer.
- **Directory Health & SYSVOL**:
  - DRS replication status (`samba-tool drs showrepl`).
  - LDB database integrity check (`dbcheck --cross-ncs`).
  - SYSVOL ACL validation and reset (`sysvolcheck` and `sysvolreset`).
  - Built-in PowerShell script for Windows DC2 SYSVOL pull synchronization (Guide Part 18.9).
- **AD Setup & Provisioning Wizard**:
  - Guided step-by-step wizard to deploy new primary DC1 or join secondary DC2.
