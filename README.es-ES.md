# Astral AD & Hybrid DNS

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo en Rust con Interfaz Web para Administración y Aprovisionamiento de Samba 4 Active Directory 2016 y BIND 9 Híbrido** — Basado en la guía de arquitectura corporativa para Linux de Euripedes Batista.

Bajo licencia **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🚀 Características (v1.4.0)

- **Backend en Rust (Axum 0.8 + Tokio)**:
  - Servidor REST de alto rendimiento en el puerto `8095`.
  - **Seguridad en Cortafuegos**: Las reglas existentes NUNCA se limpian ni vacían. Los puertos se comprueban y añaden de forma segura y no destructiva.
- **Interfaz Web Moderna (React 18 + TailwindCSS)**:
  - Multilingüe en 4 idiomas: 🇧🇷 PT-BR, 🇺🇸 EN-US, 🇪🇸 ES-ES, 🇫🇷 FR-FR.
- **Gestión Completa de Active Directory**:
  - Nivel funcional 2016 para bosque y dominio.
  - Administración de usuarios, grupos y equipos.
  - Zonas DNS con generación automática de registros inversos PTR (`in-addr.arpa`).
  - BIND 9 híbrido en `127.0.0.1:5353` como reenviador recursivo.
  - Diagnóstico DRS showrepl, dbcheck y restauración de ACLs SYSVOL.
  - Asistente de aprovisionamiento guiado para DC1 y DC2.
