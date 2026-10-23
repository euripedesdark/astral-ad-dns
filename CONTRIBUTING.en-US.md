# Contributing to Astral AD & Hybrid DNS

## Code of Conduct
This project and all contributors are governed by the Code of Conduct.

## Development Setup

### Prerequisites
* Rust 1.80+ (cargo, rustc)
* Node.js 20+ & npm 10+
* Samba 4.20+ (samba-dc, samba-client)
* BIND 9 (named)
* Chrony (chronyd)
* Step-CA & Step-CLI (Smallstep PKI)

### Build and Execution

```bash
# Backend Rust
cargo test
cargo build --release

# Frontend React
cd web
npm install
npm run build
```

## Project Structure

```
astral-ad-dns/
├── Cargo.toml                 # Rust project metadata & dependencies (Axum, Tokio, Libc)
├── Cargo.lock                 # Locked dependency versions
├── src/                       # Backend source code
│   ├── main.rs                # Application entrypoint, Axum server on port 8095
│   ├── config.rs              # Service configurations and Samba/BIND paths
│   ├── auth.rs                # Real PAM dynamic auth (root/wheel/sudo) & Samba AD / SSO
│   ├── audit.rs               # Structured operational audit log
│   ├── system.rs              # Iptables port reconciler & resolv.conf safeguard
│   ├── system/
│   │   └── firewall_migration.rs # Firewalld/ufw/nftables to iptables migrator
│   └── api/                   # Unified REST controllers
│       ├── mod.rs             # Main router (/api/*)
│       ├── provision.rs       # Domain provision, join, Schema 2019, Step-CA PKI
│       ├── dns.rs             # Forward/reverse zones and AD DNS records
│       ├── bind.rs            # Hybrid BIND 9 recursive server (port 5353)
│       ├── firewall.rs        # Port auditing and automated reconciliation
│       ├── health.rs          # DRS replication, dbcheck and SYSVOL sync
│       ├── users.rs           # Active Directory user management
│       ├── groups.rs          # Active Directory group management
│       ├── computers.rs       # Domain computer management
│       ├── diagnostics.rs     # Operational health checks
│       ├── status.rs          # Real-time daemon status
│       └── terminal.rs        # Restricted operational console
├── web/                       # React 18 SPA Frontend + Vite + Tailwind CSS
│   ├── src/
│   │   ├── main.tsx           # React entrypoint
│   │   ├── App.tsx            # Unified SPA with shared context and tabs
│   │   ├── i18n.ts            # Multilingual dictionary (pt-BR, en-US, es-ES, fr-FR)
│   │   └── components/
│   │       └── DonationModal.tsx # PIX and Wise donation modal
│   ├── package.json
│   ├── vite.config.js
│   └── dist/                  # Compiled production build
├── samba-ad-dc/               # Advanced Samba AD DC + Step-CA automation scripts
│   ├── provision_ad_step_ca.py # Full provisioning and TLS certificate renewal script
│   └── auth.env               # Environment configuration
├── dns/                       # BIND 9 hybrid configuration templates
├── nginx/                     # Nginx reverse proxy configuration templates
├── systemd/                   # systemd unit definition (astral-ad-dns.service)
└── docs/i18n/                 # Multilingual documentation
```

## Pull Request Guidelines
1. Create a descriptive feature branch from main.
2. Write unit tests for new backend capabilities.
3. Ensure both npm run build and cargo test complete cleanly.
4. Submit a Pull Request with a clear summary.
