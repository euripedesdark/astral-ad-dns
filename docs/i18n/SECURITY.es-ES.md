# Política de Seguridad

La seguridad de Astral Platform & HCI se toma en serio. Este proyecto es una
plataforma de infraestructura que controla red, firewall e identidad — un
informe bien hecho aquí importa más que la mayoría.

## Cómo Reportar

**No abras issues públicas para vulnerabilidades de seguridad.**
Repórtalo por correo electrónico: **euripedesdark@gmail.com**

Incluye la siguiente información:

* Una descripción de la vulnerabilidad
* Pasos para reproducir el problema
* El impacto potencial
* Cualquier corrección sugerida (si la hay)

## Qué esperar

* Reconoceremos tu relato en un plazo de hasta 48 horas.
* Investigaremos el problema y proporcionaremos un plazo para la corrección.
* Te reconoceremos en las notas de la versión (a menos que prefieras permanecer
  anónimo).
* Publicaremos la corrección lo antes posible y te avisaremos cuando esté
  disponible.

## Alcance

Esta política de seguridad se aplica a:

* El código de la aplicación del plano de control
* Los endpoints de la API y el proxy de autenticación ATS
* Los scripts de instalación y verificación
* La configuración del sistema y los scripts de aprovisionamiento

## Fuera de alcance

* Bibliotecas de terceros (reporta las vulnerabilidades a los proyectos
  correspondientes)
* El **servidor Graylog**, que es un proyecto separado, bajo **SSPL-1.0**
* Problemas en la documentación
* Preguntas generales sobre buenas prácticas de seguridad

## 🔐 Medidas de seguridad

El proyecto implementa las siguientes medidas:

* **Autenticación:** Spring Security con múltiples fuentes — Active Directory
  (LDAP/Kerberos) y PostgreSQL — combinadas por
  `MultiSourceAuthenticationProvider`
* **Sesión:** cookie `HttpOnly` y `SameSite=Lax`, expiración de 8 horas,
  `Secure` activado mediante `ASTRAL_COOKIE_SECURE`
* **Sesión, no token:** la sesión es con estado y se mantiene en el servidor,
  con una cookie `HttpOnly`. `/api/v1/acl/check` acepta un Bearer JWT HS256,
  pero la validación está **desactivada por defecto**
  (`ASTRAL_AUTH_JWT_ENABLED=false`) — el Auth Service todavía no emite tokens,
  así que la sesión es el único camino que funciona
* **Proxy de confianza:** `server.forward-headers-strategy=framework`, porque
  ATS y Nginx terminan TLS delante
* **Secretos:** `auth.env` permanece en disco y **fuera** del control de
  versiones
* **Base de datos:** `ddl-auto=validate` + Flyway (`db/migration/`) en ambas
  apps; la heredada `fabric/firewall/` (8040) está **retirada**, pero sigue en
  el repositorio, e `InstallerFirewall.java` todavía la implanta
* **Aislamiento de red:** la aplicación escucha solo en loopback (8081/8082);
  el puerto público es 443 vía Nginx, con TLS, y 81 responde `301` a 443
* **Verificación:** `scripts/verify-astral.sh` falla a propósito si la
  aplicación queda expuesta fuera del loopback
* **Auditoría:** pista de auditoría y aprobación humana en el plano de control
* **Cortafuegos del sistema:** configurado por
  `scripts/configure-system-firewall.sh`, con `iptables` e `ipset`
* **Antimalware:** ClamAV instalado por `installbase.sh`

## Política de divulgación

Seguimos una política de divulgación coordinada. Te pedimos que:

* Nos des un tiempo razonable para corregir el problema antes de divulgarlo
  públicamente.
* No explotes la vulnerabilidad más allá de lo necesario para demostrarla.
* No accedas ni modifiques datos pertenecientes a otros usuarios.

## 🌐 Otros idiomas

| Idioma | Documento |
|--------|-----------|
| 🇧🇷 Português (Brasil) | [SECURITY.pt-BR.md](SECURITY.pt-BR.md) |
| 🇺🇸 English | [SECURITY.en-US.md](SECURITY.en-US.md) |
| 🇪🇸 Español | [SECURITY.es-ES.md](SECURITY.es-ES.md) |
| 🇫🇷 Français | [SECURITY.fr-FR.md](SECURITY.fr-FR.md) |