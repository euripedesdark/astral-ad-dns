# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md"><b>🇪🇸 Español (España)</b></a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo en Rust con Interfaz Web para Administración, Aprovisionamiento y Gestión de Samba 4 Active Directory (Nivel Funcional 2016) y BIND 9 Híbrido** — Desarrollado a partir de la guía técnica exhaustiva de arquitectura corporativa para Linux de Euripedes Batista.

Distribuido bajo licencia **GNU AGPL v3**. Consulte [`LICENSE.md`](LICENSE.md).

---

## 📋 Índice
1. [Preparación del Servidor por Distribución Linux](#1-preparación-del-servidor-por-distribución-linux)
2. [Instalación y Despliegue Automatizado (`deploy_ad_dns.py`)](#2-instalación-y-despliegue-automatizado-deploy_ad_dnspy)
3. [Despliegue Manual Alternativo (Cargo y Systemd)](#3-despliegue-manual-alternativo-cargo-y-systemd)
4. [Asistente Web de Aprovisionamiento y Topologías](#4-asistente-web-de-aprovisionamiento-y-topologías)
5. [Infraestructura de Clave Pública (PKI Step-CA y LDAPS)](#5-infraestructura-de-clave-pública-pki-step-ca-y-ldaps)
6. [Resolución DNS Híbrida con BIND 9 y SELinux](#6-resolución-dns-híbrida-con-bind-9-y-selinux)
7. [Despliegue Limpio, Reincorporación y Limpieza de Bases Huérfanas](#7-despliegue-limpio-reincorporación-y-limpieza-de-bases-huérfanas)
8. [Verificación Operativa y Diagnóstico](#8-verificación-operativa-y-diagnóstico)
9. [Seguridad del Cortafuegos y Registro de Auditoría](#9-seguridad-del-cortafuegos-y-registro-de-auditoría)

---

## 1. Preparación del Servidor por Distribución Linux

Antes de iniciar el asistente web para crear o unir un controlador al dominio, configure los paquetes y repositorios corporativos requeridos:

### Preparación Rápida Automatizada
El script `deploy_ad_dns.py` incluye una opción dedicada que configura repositorios corporativos verificados por GPG e instala todos los binarios esenciales sin modificar la base de datos de Samba ni requerir compilación:

```bash
# Configura repositorios e instala dependencias en Linux sin compilar el panel web
python3 deploy_ad_dns.py --prepare-ad-only
```

### Particularidades por Distribución

* **RHEL 10 / AlmaLinux 10 / Rocky Linux 10 (EL10):**
  - Importa la clave oficial `RPM-GPG-KEY-TISSAMBA-10`.
  - Habilita el repositorio Tranquil IT: `https://samba.tranquil.it/redhat10/samba-4.24/`.
  - Habilita CRB (`dnf config-manager --set-enabled crb`) y EPEL 10.
  - Instala: `samba`, `samba-dc`, `samba-winbind`, `samba-winbind-clients`, `krb5-workstation`, `ldb-tools`, `bind`, `bind-utils`, `chrony`, `python3-setproctitle`, `policycoreutils-python-utils`.
* **RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (EL9):**
  - Importa la clave `RPM-GPG-KEY-TISSAMBA-9` y el repositorio `https://samba.tranquil.it/redhat9/samba-4.24/`.
  - Habilita CRB y EPEL 9.
* **Debian 12 (Bookworm) / Debian 13 (Trixie):**
  - Importa la clave GPG oficial Tranquil IT en `/usr/share/keyrings/tissamba.gpg` (`https://samba.tranquil.it/tissamba-pubkey.gpg`).
  - Habilita el repositorio oficial Tranquil IT: `deb [signed-by=/usr/share/keyrings/tissamba.gpg] https://samba.tranquil.it/debian/samba-4.24/ $(lsb_release -cs) main`.
  - Instala los paquetes especializados de Samba AD DC: `samba`, `samba-ad-dc`, `winbind`, `libnss-winbind`, `krb5-user`, `smbclient`, `ldb-tools`, `python3-samba`, `bind9`, `bind9utils`, `chrony`.
* **Fedora 44 / 45:**
  - Emplea los paquetes oficiales nativos de la distribución (`dnf install -y samba samba-dc bind bind-utils chrony krb5-workstation`). No requiere repositorios de terceros.
* **Arch Linux:**
  - Instalación oficial mediante pacman: `pacman -S --needed samba bind chrony krb5`. No requiere repositorios de terceros.
* **openSUSE Leap 15.x / Tumbleweed / SUSE Linux Enterprise (SLES):**
  - Utiliza los paquetes oficiales nativos de la distribución (`zypper install -y samba samba-ad-dc samba-client samba-winbind krb5-client bind bind-utils chrony`). No requiere repositorios de Tranquil IT.
  - Servicio AD DC: `samba-ad-dc.service` (unidades conflictivas desactivadas: `smb`, `nmb`, `winbind`).
  - DNS BIND 9: servicio `named.service` con anulación systemd (`named.service.d/override.conf` con `ReadWritePaths`) y reglas AppArmor para `/var/lib/samba/bind-dns`.
* **Ubuntu 24.04 LTS:**
  - Emplea los paquetes oficiales nativos de la distribución (Samba 4.19, emplea los mismos paquetes que Debian: `apt-get install -y samba samba-ad-dc winbind libnss-winbind krb5-user smbclient ldb-tools python3-samba bind9 bind9utils chrony`). No debe utilizar paquetes Tranquil IT.

### Matriz Comparativa: Daemons, Servicios y Seguridad

| Característica / Rol | Fedora (44/45) | openSUSE / SLES | Debian (12/13) | Ubuntu 24.04 LTS | RHEL / EL (9/10) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Servicio AD DC** | `samba.service` (samba-dc) | `samba-ad-dc.service` | `samba-ad-dc.service` | `samba-ad-dc.service` | `samba.service` (samba-dc) |
| **Servicios Miembro/File** | `smb`, `nmb`, `winbind` | `smb`, `nmb`, `winbind` | `smbd`, `nmbd`, `winbind` | `smbd`, `nmbd`, `winbind` | `smb`, `nmb`, `winbind` |
| **Gestor de Paquetes** | `dnf` | `zypper` | `apt` | `apt` | `dnf` |
| **Repositorio AD DC** | Oficial Fedora | Oficial SUSE / OBS | Tranquil IT Samba 4.24 | Oficial Ubuntu (4.19) | Tranquil IT + CRB/EPEL |
| **Paquete Kerberos** | `krb5-workstation` | `krb5-client` | `krb5-user` | `krb5-user` | `krb5-workstation` |
| **Servicio BIND DNS** | `named.service` | `named.service` | `named.service` (`bind9`) | `named.service` (`bind9`) | `named.service` |
| **Directorio BIND** | `/var/named` | `/var/lib/named` | `/var/cache/bind` | `/var/cache/bind` | `/var/named` |
| **Seguridad MAC** | SELinux | AppArmor | AppArmor | AppArmor | SELinux |

> ### ❓ Pregunta Frecuente: ¿El asistente web instala los paquetes de Samba automáticamente?
> **SÍ, el asistente web cuenta con una rutina de instalación automática de dependencias (`install_dependencies`), pero considere los requisitos de su distribución:**
> - **Fedora, openSUSE / SUSE, Arch Linux y Ubuntu**: Utilizan directamente los paquetes oficiales de sus repositorios del sistema (sin repositorios de terceros). El asistente web detecta paquetes faltantes y los instala automáticamente mediante el gestor nativo (`dnf`, `zypper`, `pacman`, `apt`).
> - **Debian (12/13) y Enterprise Linux (RHEL 9/10, AlmaLinux 9/10, Rocky Linux 9/10)**: Estas distribuciones requieren los paquetes especializados de Controlador de Dominio (`samba-ad-dc` / `samba-dc`) proporcionados por Tranquil IT. Ejecute previamente:
>   ```bash
>   python3 deploy_ad_dns.py --prepare-ad-only
>   ```
>   Este comando configura el repositorio corporativo Tranquil IT (con clave GPG) y habilita CRB/EPEL. A partir de ese momento, tanto la terminal como el **asistente web** podrán instalar y actualizar todos los paquetes de Samba AD automáticamente.

---

## 2. Instalación y Despliegue Automatizado (`deploy_ad_dns.py`)

El script `deploy_ad_dns.py` automatiza el ciclo operativo integral: compilación en modo release optimizado del backend en Rust, empaquetado del frontend Vite/React, instalación en `/opt/astral-ad-dns/`, configuración y activación de la unidad systemd y apertura segura del puerto web en el cortafuegos.

### ⚠️ Ejecución Sin Solicitar Git (`--skip-git`)
Por defecto, para ejecutar el despliegue localmente en el servidor **sin que el script solicite credenciales de Git ni intente un `git push`** al repositorio remoto, añada siempre el parámetro `--skip-git`:

```bash
# 1. Despliegue completo local sin interacción con Git (Recomendado para servidores)
python3 deploy_ad_dns.py --skip-git

# 2. Despliegue completo con preparación automática de paquetes de Samba AD (sin Git)
python3 deploy_ad_dns.py --prepare-ad --skip-git

# 3. Solo preparar repositorios e instalar paquetes de Samba AD (sin compilar web ni usar Git)
python3 deploy_ad_dns.py --prepare-ad-only
```

> **¿Por qué usar `--skip-git`?** Sin este parámetro, el script intenta ejecutar `git push origin <rama>` en el paso final. En servidores donde no se han guardado credenciales de Git (o en despliegues manuales), el script puede detenerse solicitando usuario/contraseña o fallar. La opción `--skip-git` omite ese paso y garantiza un despliegue 100% local, rápido y sin interrupciones.

### Acciones del Despliegue Automatizado:
1. **Compilación del Backend**: Ejecuta `cargo build --release --bin astral-ad-dns`.
2. **Construcción del Frontend**: Ejecuta `npm install` y `npm run build` en la carpeta `web/`.
3. **Instalación en `/opt/astral-ad-dns`**:
   - Binario copiado a `/opt/astral-ad-dns/astral-ad-dns`.
   - Archivos estáticos en `/opt/astral-ad-dns/web/dist/`.
   - Scripts de aprovisionamiento en `/opt/astral-ad-dns/samba-ad-dc/`.
   - Enlace simbólico generado en `/usr/local/bin/astral-ad-dns`.
4. **Servicio Systemd**:
   - Genera `/etc/systemd/system/astral-ad-dns.service`.
   - Ejecuta `systemctl daemon-reload`, habilita e inicia el servicio.
5. **Cortafuegos Seguro**:
   - Comprueba e inserta la regla para el puerto TCP 8095 en `iptables` sin vaciar reglas activas.
6. **Verificación de Salud**:
   - Comprueba la respuesta HTTP local (`http://127.0.0.1:8095/api/auth/providers`).

### Actualización Rápida en Nodos Secundarios (DC2 / RODC)
Para sincronizar scripts operacionales actualizados en controladores secundarios sin recompilar el binario Rust:
```bash
cd ~/astral-ad-dns
git pull origin main
sudo cp -r samba-ad-dc/* /opt/astral-ad-dns/samba-ad-dc/
sudo systemctl restart astral-ad-dns.service
```

---

## 3. Despliegue Manual Alternativo (Cargo y Systemd)

Si prefiere compilar e instalar manualmente los componentes:

```bash
# 1. Compilar Backend en Rust
cargo build --release --bin astral-ad-dns

# 2. Compilar Frontend React / Vite
cd web
npm install
npm run build
cd ..

# 3. Crear Directorios de Producción
sudo mkdir -p /opt/astral-ad-dns/web
sudo cp target/release/astral-ad-dns /opt/astral-ad-dns/
sudo cp -r web/dist /opt/astral-ad-dns/web/
sudo cp -r samba-ad-dc /opt/astral-ad-dns/
sudo ln -sf /opt/astral-ad-dns/astral-ad-dns /usr/local/bin/astral-ad-dns

# 4. Configurar e Iniciar la Unidad Systemd
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service

# 5. Abrir en el Navegador
# Ingrese a http://<IP_DEL_SERVIDOR>:8095
```

---

## 4. Asistente Web de Aprovisionamiento y Topologías

Acceda a `http://<IP_DEL_SERVIDOR>:8095` y haga clic en **"Asistente de Aprovisionamiento"**. El sistema soporta cuatro topologías corporativas:

### 1. Nuevo Dominio Primario (DC1)
* Creación de un bosque nuevo de Active Directory con nivel funcional **2016**.
* Generación del reino Kerberos, dominio NetBIOS, Catálogo Global y backend DNS (`SAMBA_INTERNAL`).
* Inicialización opcional de la entidad certificadora Step-CA integrada para certificados LDAPS.

### 2. Controlador Secundario Réplica Lectura/Escritura (DC2 RW)
* Incorporación del servidor como Domain Controller adicional en el bosque existente.
* Replicación bidireccional Multi-Master del directorio mediante DRS (Directory Replication Services).
* Sincronización automatizada de SYSVOL desde el controlador principal con preservación de ACLs NT.
* Sincronización de reloj estricta y firmada para Kerberos (`ntp_signd`).

### 3. Controlador de Dominio de Solo Lectura (RODC)
* Indicado para sucursales u oficinas remotas con menor nivel de seguridad física perimetral.
* Base de datos LDB local montada en modo solo lectura; las contraseñas de usuario no se almacenan en caché por defecto.
* Validación DRS en el socio evitando llamadas RPC privilegiadas que colisionen con KDC MIT.

### 4. Servidor Miembro del Dominio (MEMBER)
* Servidor Linux integrado en el directorio para autenticación centralizada (Winbind / PAM / NSS).
* No aloja bases de datos de directorio (`sam.ldb`) ni consume recursos de replicación de controladores.

---

## 5. Infraestructura de Clave Pública (PKI Step-CA y LDAPS)

Astral AD proporciona soporte corporativo de certificados digitales con validación rigurosa de confianza:

* **Jerarquía de Certificados en 2 Niveles**:
  $$\text{Root CA} \longrightarrow \text{Intermediate CA} \longrightarrow \text{Certificado del Controlador DC}$$
* **Validación de Cadena Completa en la Incorporación**:
  - En nodos réplica (DC2 / RODC), el asistente descarga automáticamente el certificado intermedio oficial por HTTPS (`https://<IP_CA>:9444/intermediates.pem`).
  - OpenSSL valida la cadena completa (`-CAfile trusted-step-root.crt -untrusted intermediates.pem dc.crt`) evitando errores de emisor local no reconocido.
  - El parámetro `tls cafile` de Samba se configura con la cadena completa unificada.
* **Renovación Automatizada**:
  - Configura el temporizador systemd `astral-ad-tls-renew.timer` para inspeccionar y renovar certificados cada 15 minutos sin interrupción de servicio.

---

## 6. Resolución DNS Híbrida con BIND 9 y SELinux

La plataforma elimina los conflictos entre los registros internos de AD y la navegación recursiva hacia internet:

* **Puerto 53 (UDP/TCP)**: Asignado exclusivamente a `SAMBA_INTERNAL`, con autoridad sobre la zona de dominio y registros `_msdcs`.
* **Puerto 5353 (UDP/TCP)**: Instancia aislada de **BIND 9** configurada exclusivamente como resolvedor recursivo en `127.0.0.1:5353`.
* **Integración con SELinux**:
  - El asistente inspecciona puertos existentes con `semanage port -l`.
  - Asigna con seguridad la etiqueta `dns_port_t` al puerto 5353 incluso en presencia de políticas concurrentes como `howl_port_t`, manteniendo SELinux en modo `Enforcing`.

---

## 7. Despliegue Limpio, Reincorporación y Limpieza de Bases Huérfanas

Al reutilizar servidores previamente configurados o que contengan bases de datos de pruebas:

* **Limpieza de Bases Huérfanas**:
  - Cuando se habilita el despliegue limpio (`clean_existing`, `rejoin` o `overwrite_existing`), el sistema autoriza el borrado seguro de bases pertenecientes a dominios previos (por ejemplo, entornos de prueba como `ASTRAL.CELESTE`).
  - Detiene y elimina de forma automática cualquier servicio heredado de Step-CA que perteneciera al dominio anterior.
* **Copia de Seguridad Automática**:
  - Antes de cualquier eliminación, el asistente genera una instantánea criptográfica en `/var/backups/astral-ad-dns/provision/<ID>/` con el estado previo de Samba, cortafuegos y manifiestos de recuperación.
* **Despromoción Segura**:
  - Si el servidor figura registrado en el socio, ejecuta `samba-tool domain demote --remove-other-dead-server` para no dejar metadats residuales en el bosque.

---

## 8. Verificación Operativa y Diagnóstico

Compruebe la salud del dominio directamente desde la consola web (pestañas **Checklist** y **Diagnóstico**) o desde la terminal:

```bash
# 1. Comprobar estado de replicación DRS con el socio
sudo samba-tool drs showrepl

# 2. Validar integridad estructural de la base de datos LDB
sudo samba-tool dbcheck --cross-ncs

# 3. Validar sintaxis del archivo smb.conf
testparm -s

# 4. Consultar registros DNS de localización de servicio (SRV)
dig @127.0.0.1 _ldap._tcp.dc._msdcs.<DOMINIO> SRV +short

# 5. Comprobar sincronización de hora para Kerberos
chronyc tracking

# 6. Validar apretón de manos LDAPS y cadena de certificados
openssl s_client -connect 127.0.0.1:636 -showcerts < /dev/null
```

---

## 9. Seguridad del Cortafuegos y Registro de Auditoría

* **Bloqueos Anti-Destrucción (`/api/firewall`)**:
  - El motor Rust rechaza comandos destructivos que contengan `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` o `nft flush`.
  - Inserción idempotente mediante `iptables -I INPUT 1` exclusivamente para puertos pendientes.
* **Registro de Auditoría en Memoria (`/api/audit`)**:
  - Búfer circular de hasta 500 eventos con marcas de tiempo, operadores, acciones, estados e identificadores de correlación.
  - Ocultación estricta de credenciales en todos los registros.

---

## 📄 Licencia

Este proyecto es software libre bajo la licencia **GNU Affero General Public License v3.0** (`AGPL-3.0`). Consulte [`LICENSE.md`](LICENSE.md) para más detalles.
