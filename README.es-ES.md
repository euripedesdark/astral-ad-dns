# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md"><b>🇪🇸 Español (España)</b></a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo en Rust con Interfaz Web para Administración y Aprovisionamiento de Samba 4 Active Directory 2016 y BIND 9 Híbrido** — Basado en la guía técnica de arquitectura corporativa para Linux de Euripedes Batista.

Bajo licencia **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🚀 Novedades de la Versión 1.5.0

### 1. Panel Operacional y Diagnóstico de Salud
- **Indicador de Salud Global**: Distintivo inequívoco y estandarizado (`operational`, `degraded`, `unavailable`, `unknown`) en el encabezado y en la API (`/api/status`).
- **Lista de Verificación Operacional Interactiva (`/api/checks`)**: Suite automatizada ejecutada desde la interfaz con medición de latencia en milisegundos para:
  - `testparm -s` (Validación sintáctica de `smb.conf`).
  - `samba-tool dbcheck --cross-ncs` (Integridad estructural de más de 3.900 objetos del directorio LDB).
  - `chronyc tracking` (Sincronización de reloj, estrato y desviación para Kerberos).
  - `klist` (Validación de tickets locales Kerberos).
  - Localizadores DNS SRV (`_ldap._tcp`, `_kerberos._tcp`, `_kerberos._udp`, `_kpasswd._udp`).

### 2. Diagnóstico Profundo de Infraestructura y Dependencias (`/api/diagnostics`)
Pestaña dedicada con escaneo continuo, latencias, causas probables y recomendaciones prácticas para 10 subsistemas clave:
- **Motor REST y Consola Web**: Tiempo de respuesta inmediato del runtime Axum/Tokio.
- **Servicio Samba Active Directory**: Estado del servicio e integridad en systemd.
- **Puertos de Autenticación**: Sockets de escucha LDAP (TCP 389) y Kerberos (TCP 88).
- **Servidor BIND 9 (Hybrid DNS)**: Resolución recursiva aislada en `127.0.0.1:5353`.
- **Resolución de Registros SRV**: Verificación de resolución DNS local mediante `127.0.0.1`.
- **Sincronización de Tiempo Chrony NTP**: Socket firmado Kerberos (`/var/lib/samba/ntp_signd`).
- **Dependencias del SO**: Existencia de binarios (`samba-tool`, `named`, `chronyc`, `iptables`, `host`, `klist`).
- **Archivos y SAM LDB**: Presencia y permisos de `smb.conf`, `sam.ldb` y `krb5.conf`.
- **Políticas de Seguridad SELinux**: Modo de operación (`Enforcing` / `Permissive` / `Disabled`).
- **Consistencia de la Base de Datos**: Integridad de particiones y estado de replicación.

### 3. Gestión Segura del Cortafuegos (`/api/firewall`)
- **Garantía Estricta de No Destrucción**: Bloqueo tokenizado en el backend contra comandos que contengan `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` o `nft flush`.
- **Auditoría de Puertos**: Comprobación continua de los 19 puertos estándar con `iptables -C INPUT`.
- **Apertura No Destructiva**: Inserción segura con `iptables -I INPUT 1` y soporte para simulación preventiva (`dry_run`).

### 4. Registro de Auditoría e Historial Operacional (`/api/audit`)
- Búfer circular en memoria (hasta 500 eventos) con identificador de correlación (`evt_...`), operador, acción, objetivo, modo, estado y detalles.
- Filtros interactivos por modo (Todos / Solo Simulaciones / Solo Ejecuciones Reales) y búsqueda de texto.

### 5. Modo de Simulación Preventiva (`dry_run`) y Validación Previa
- Soporte para simulación en aprovisionamiento (`/api/provision`), usuarios (`/api/users`), grupos (`/api/groups`), equipos (`/api/computers`), DNS (`/api/dns`) y BIND 9 (`/api/bind`).
- **Bloqueos Anti-Eliminación**: Protección contra eliminación accidental del Controlador de Dominio (`DC-ERP`) y grupos estructurales ("Domain Admins", etc.).
- **Enmascaramiento de Contraseñas**: Ocultación automática de credenciales sensibles en todos los registros.

### 6. Interfaz Web Moderna con Selector de Idioma
- Menú desplegable (`<select>`) en el encabezado superior para cambio instantáneo entre 4 idiomas con persistencia en `localStorage`:
  - 🇧🇷 Português (Brasil)
  - 🇺🇸 English (US)
  - 🇪🇸 Español (España)
  - 🇫🇷 Français (France)
- 100% de la interfaz traducida en los 4 idiomas.

### 7. Política Unificada de Acceso y Autenticación Multiproveedor
Implementación de la política corporativa unificada de autenticación y autorización:
- **Samba Active Directory / OAuth2**: Autenticación para usuarios y administradores de dominio con mapeo de grupos LDAP/Kerberos o mediante tokens SSO de `astral-auth-service`.
- **Linux Local (Root / Sudo)**: Inicio de sesión para administradores del sistema operativo pertenecientes al grupo `wheel`/`sudo` o superusuario `root`.
- **Superusuario PostgreSQL**: Validación directa de credenciales para cualquier usuario de base de dados con `rolsuper = true` (ej: `postgres`).
- **Soporte para Bearer Token y Cookies de Sesión**: Validación simultánea de encabezados `Authorization: Bearer <jwt>` y cookies `sso_token` / `astral_token`.
- **Rutas de Autenticación**:
  - `POST /api/auth/login`: Validación de credenciales y emisión de token JWT.
  - `GET /api/auth/me`: Consulta de identidad y privilegios del operador activo.
  - `POST /api/auth/logout`: Cierre de sesión e invalidación de cookies.
  - `GET /api/auth/providers`: Catálogo de métodos de autenticación soportados.
- **Ámbitos Preservados**: Aplicado transversalmente manteniendo independientes únicamente `astral-saas-erp` (Java) y la interfaz web IAM de `auth-service`.

---

## 🛠️ Instalación y Despliegue

### Compilación del Backend (Rust)
```bash
cargo build --release --bin astral-ad-dns
```

### Compilación del Frontend (Web GUI)
```bash
cd web
npm install
npm run build
cd ..
```

### Servicio systemd
```bash
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service
```

Acceda en el navegador: `http://<SU_IP>:8095/` (o mediante el proxy inverso `/ad/`).

---

## 📄 Licencia y Contribución

- Licencia: **GNU Affero General Public License v3.0** ([`LICENSE.md`](LICENSE.md))
- Guía de Contribución: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Política de Seguridad: [`SECURITY.md`](SECURITY.md)
- Código de Conducta: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
