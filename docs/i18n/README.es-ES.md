# Astral AD & Hybrid DNS

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Samba](https://img.shields.io/badge/Samba-4-green.svg)
![Kerberos](https://img.shields.io/badge/Auth-Kerberos%20%2F%20LDAPS-orange.svg)
![DNS](https://img.shields.io/badge/DNS-Contextual%20Resolver-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)

**Controlador de Dominio Corporativo Samba 4 y Resolución DNS Híbrida** — Módulo especializado del ecosistema Astral para el servicio de directorio Active Directory (AD DC), autenticación centralizada (LDAPS/Kerberos) y resolución DNS inteligente con selección contextual de servidores upstream.

Este proyecto está bajo la licencia **GNU AGPL v3**. Consulte [`LICENSE.md`](LICENSE.md).

---

## 🎯 Características Principales

- **Samba 4 Active Directory Domain Controller (AD DC)**:
  - Scripts de aprovisionamiento 100% automatizados para Fedora/RHEL, Debian 13 y Arch Linux.
  - Soporte para certificados SSL/TLS automáticos (Step-CA) y LDAPS en el puerto 636.
  - Compatibilidad total con clientes Windows (GPO, RSAT) y estaciones Linux integradas mediante SSSD/PAM.
  - Gestión segura de credenciales mediante el archivo aislado `auth.env`.
- **DNS Sensible al Contexto e Híbrido**:
  - Clasificación y selección sin conexión de proveedores DNS globales de confianza (DNSSEC = true, fiabilidad >= 0.95).
  - Integración nativa con Pi-hole y dnsmasq para el bloqueo de anuncios y telemetría.
  - Base de datos local con más de 8 MB de servidores DNS en todo el mundo (`nameservers.csv`).

---

## 🛠️ Stack Tecnológico

| Capa | Tecnología | Propósito |
|---|---|---|
| **Servicio de Directorio** | Samba 4 AD DC | Emulación completa de Active Directory, LDAP, Kerberos KDC |
| **Criptografía e Identidad** | OpenSSL / Step-CA | PKI automática, LDAPS (TCP 636), certificados X.509 |
| **Resolución DNS** | BIND9 DLZ / dnsmasq / Pi-hole | DNS autoritativo y filtrado contextual |
| **Motor de Automatización** | Python 3.12+ | Aprovisionamiento sin intervención manual |

---

## 💖 Apoye el Proyecto

**Transferencia Internacional (Wise):**
- **Titular:** Euripedes Batista de Paiva Junior
- **Routing number (Wire / ACH):** `101019628`
- **Número de cuenta:** `215822927677`
- **Banco:** Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States
- **SWIFT / BIC:** `TRWIUS35XXX`

**PIX (Brasil):** `24adc62c-b073-4587-974d-03fe35f6733f`

---

(c) 2026 Astral AD & Hybrid DNS — **Creado por: Euripedes Batista de Paiva Junior**
