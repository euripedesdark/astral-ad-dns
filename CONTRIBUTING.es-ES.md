# Contribuyendo a Astral AD & Hybrid DNS

## Código de Conducta
Este proyecto y sus participantes se rigen por el Código de Conducta.

## Configuración de Desarrollo

### Requisitos Previos
* Rust 1.80+ (cargo, rustc)
* Node.js 20+ & npm 10+
* Samba 4.20+ (samba-dc, samba-client)
* BIND 9 (named)
* Chrony (chronyd)
* Step-CA & Step-CLI (Smallstep PKI)

### Compilación y Ejecución

```bash
# Backend Rust
cargo test
cargo build --release

# Frontend React
cd web
npm install
npm run build
```

## Estructura del Proyecto

```
astral-ad-dns/
├── Cargo.toml                 # Metadatos y dependencias Rust (Axum, Tokio, Libc)
├── Cargo.lock                 # Versiones bloqueadas de dependencias
├── src/                       # Código fuente backend
│   ├── main.rs                # Punto de entrada, servidor Axum en puerto 8095
│   ├── config.rs              # Configuraciones de Samba, BIND y rutas
│   ├── auth.rs                # Autenticación real PAM (root/wheel/sudo) y Samba AD / SSO
│   ├── audit.rs               # Registro de auditoría operativa
│   ├── system.rs              # Conciliador de iptables y protección resolv.conf
│   ├── system/
│   │   └── firewall_migration.rs # Migrador de firewalld/ufw/nftables a iptables
│   └── api/                   # Controladores REST unificados
│       ├── mod.rs             # Enrutador principal (/api/*)
│       ├── provision.rs       # Aprovisionamiento DC, Join, Schema 2019, Step-CA PKI
│       ├── dns.rs             # Zonas directas, inversas y registros DNS del AD
│       ├── bind.rs            # Servidor BIND 9 híbrido recursivo (puerto 5353)
│       ├── firewall.rs        # Auditoría y apertura de puertos de red
│       ├── health.rs          # Replicación DRS, dbcheck y SYSVOL
│       ├── users.rs           # Gestión de usuarios del Active Directory
│       ├── groups.rs          # Gestión de grupos del Active Directory
│       ├── computers.rs       # Gestión de equipos en el dominio
│       ├── diagnostics.rs     # Diagnósticos del sistema
│       ├── status.rs          # Estado en tiempo real de servicios
│       └── terminal.rs        # Consola administrativa restringida
├── web/                       # Interfaz SPA React 18 + Vite + Tailwind CSS
│   ├── src/
│   │   ├── main.tsx           # Punto de montaje React
│   │   ├── App.tsx            # Navegación unificada con contexto compartido
│   │   ├── i18n.ts            # Diccionario multilenguaje (pt-BR, en-US, es-ES, fr-FR)
│   │   └── components/
│   │       └── DonationModal.tsx # Modal de donaciones PIX y Wise
│   ├── package.json
│   ├── vite.config.js
│   └── dist/                  # Compilación estática de producción
├── samba-ad-dc/               # Scripts avanzados Samba AD DC + Step-CA PKI
│   ├── provision_ad_step_ca.py # Script completo de despliegue y renovación TLS
│   └── auth.env               # Variables de entorno
├── dns/                       # Plantillas de configuración BIND híbrido
├── nginx/                     # Plantillas de proxy inverso Nginx
├── systemd/                   # Servicio systemd (astral-ad-dns.service)
└── docs/i18n/                 # Documentación multilenguaje
```

## Directrices para Pull Requests
1. Cree una rama descriptiva a partir de main.
2. Añada pruebas unitarias para nuevas funcionalidades.
3. Compruebe que npm run build y cargo test se ejecuten sin errores.
4. Envíe el Pull Request con documentación de cambios.
