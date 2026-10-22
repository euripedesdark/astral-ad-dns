# Security Policy

We take the security of Astral Platform & HCI seriously. This project is an
infrastructure platform controlling networking, firewall and identity — a
well-made report here matters more than most.

## How to Report

**Do not open public GitHub issues for security vulnerabilities.**
Email us at: **euripedesdark@gmail.com**

Include the following information:

* A description of the vulnerability
* Steps to reproduce the issue
* The potential impact
* Any suggested fixes (if available)

## What to Expect

* We will acknowledge your report within 48 hours.
* We will investigate the issue and provide a timeline for a fix.
* We will credit you in the release notes (unless you prefer to remain
  anonymous).
* We will release a fix as soon as possible and notify you when it is available.

## Scope

This security policy applies to:

* The control plane application code
* The API endpoints and the ATS authentication proxy
* The installation and verification scripts
* System configuration and provisioning scripts

## Out of Scope

* Third-party libraries (please report vulnerabilities to the respective
  projects)
* The **Graylog server**, which is a separate project under **SSPL-1.0**
* Issues in the documentation
* General questions about security best practices

## 🔐 Security Measures

The project implements the following security measures:

* **Authentication:** Spring Security with multiple sources — Active Directory
  (LDAP/Kerberos) and PostgreSQL — combined by
  `MultiSourceAuthenticationProvider`
* **Session:** `HttpOnly` and `SameSite=Lax` cookie, 8-hour expiry, `Secure`
  enabled via `ASTRAL_COOKIE_SECURE`
* **Session, not token:** the session is stateful and held on the server, with
  an `HttpOnly` cookie. `/api/v1/acl/check` accepts a Bearer HS256 JWT, but
  validation is **off by default** (`ASTRAL_AUTH_JWT_ENABLED=false`) — the Auth
  Service does not issue tokens yet, so the session is the only path that works
* **Trusted proxy:** `server.forward-headers-strategy=framework`, because ATS
  and Nginx terminate TLS in front
* **Secrets:** `auth.env` stays on disk and **out of** version control
* **Database:** `ddl-auto=validate` + Flyway (`db/migration/`) in both apps; the
  legacy `fabric/firewall/` (8040) is **retired** but still in the repository,
  and `InstallerFirewall.java` still deploys it
* **Network isolation:** the application listens on loopback only (8081/8082);
  the public port is 443 via Nginx, with TLS, and 81 answers `301` to 443
* **Verification:** `scripts/verify-astral.sh` deliberately fails if the
  application is exposed outside loopback
* **Audit:** audit trail and human approval in the control plane
* **System firewall:** configured by `scripts/configure-system-firewall.sh`,
  with `iptables` and `ipset`
* **Anti-malware:** ClamAV installed by `installbase.sh`

## Disclosure Policy

We follow a coordinated disclosure policy. We ask that you:

* Give us a reasonable time to fix the issue before disclosing it publicly.
* Do not exploit the vulnerability beyond what is necessary to demonstrate it.
* Do not access or modify data belonging to other users.

## 🌐 Other languages

| Language | Document |
|----------|----------|
| 🇧🇷 Português (Brasil) | [SECURITY.pt-BR.md](SECURITY.pt-BR.md) |
| 🇺🇸 English | [SECURITY.en-US.md](SECURITY.en-US.md) |
| 🇪🇸 Español | [SECURITY.es-ES.md](SECURITY.es-ES.md) |
| 🇫🇷 Français | [SECURITY.fr-FR.md](SECURITY.fr-FR.md) |