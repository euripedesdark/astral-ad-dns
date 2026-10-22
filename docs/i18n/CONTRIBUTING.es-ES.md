# Contribuyendo a Astral Platform & HCI

¡Gracias por tu interés en contribuir a Astral Platform & HCI! Este documento
proporciona las directrices para contribuir al proyecto.

## Código de Conducta

Este proyecto y todos los participantes se rigen por el
[Código de Conducta](../../CODE_OF_CONDUCT.md). Al participar, se espera que
respetes este código.

## ¿Cómo puedo contribuir?

### Reportando errores

Antes de crear un informe de error, revisa las issues existentes: puede que el
problema ya esté reportado. Al crear un informe, incluye el máximo de detalles
posible:

* Un título claro y descriptivo
* Los pasos exactos para reproducir el problema
* El comportamiento que observaste tras seguir los pasos
* El comportamiento que esperabas ver
* Capturas de pantalla, si corresponde
* Tu entorno (distribución y versión, Java, Node, navegador, etc.)

> 💡 Este proyecto controla red, firewall e identidad. Al reportar un error de
> firewall o DNS, incluye siempre el `diff` que Astral produjo entre el estado
> deseado y el observado. Es la información más valiosa disponible aquí.

### Sugiriendo mejoras

Las sugerencias se registran como issues de GitHub. Al crear una, incluye:

* Un título claro y descriptivo
* Una descripción detallada de la mejora propuesta
* Cualquier ejemplo relevante
* La motivación de la mejora

### Pull Requests

1. Haz un fork del repositorio y crea tu rama a partir de `main`.
2. Si añadiste código que debería probarse, añade pruebas.
3. Si cambiaste APIs o contratos, actualiza la documentación.
4. Asegúrate de que la suite de pruebas pasa.
5. Comprueba que tu código sigue el estilo de código existente.
6. Crea un pull request con título y descripción claros.

## ⚠️ Reglas innegociables

Estas tres reglas provienen de decisiones de arquitectura ya tomadas. Un PR que
las vulnere será rechazado, aunque el código sea correcto.

### 1. El instalador nunca escribe código fuente

`scripts/install-astral.sh` es el instalador **único**. Es bash puro y **nunca**
genera `pom.xml` ni ningún archivo `.java`.

> **Por qué:** un instalador que escribe el código que él mismo compila
> sobrescribe trabajo funcional con código muerto. El código generado va al
> repositorio y pasa por revisión.

Si tu PR necesita generar código, el código generado va al repositorio.

### 2. `ddl-auto` es `validate`, y quien migra es Flyway

No añadas `@Entity` sin una migración explícita en
`src/main/resources/db/migration/`.

> **Por qué:** `validate` hace que el arranque **falle** cuando la base no
> coincide con el Java, en lugar de fingir que todo está bien. Y la app heredada
> `fabric/firewall/` (8040) está **retirada pero sigue en el repositorio** — y
> `InstallerFirewall.java` todavía la implanta —, que es una de las dos cosas
> que la migración a `src/main/java/com/astral/fabric/` tiene que terminar.

### 3. Sesión en la UI, y el Bearer del ATS desactivado por defecto

La sesión es con estado, en el servidor, con una cookie `HttpOnly`. No
introduzcas autenticación por token en el panel sin discutir antes el cambio de
modelo — ATS y Nginx dependen de la cabecera de proxy confiable.

Hay una excepción: `GET /api/v1/acl/check` **acepta** un Bearer JWT HS256, y
está **desactivada por defecto** (`ASTRAL_AUTH_JWT_ENABLED=false`). El
BrasilCloud Auth Service todavía no emite tokens, y validar un JWT que nadie
emite es trabajo por nada. Si vas a activarlo, lee antes la
[guía de integración](../../docs/GUIA-INTEGRACAO-AUTH-SERVICE.md) — sobre todo
la sección 28, sobre lo que exigirá la emisión.

## 🛠 Configuración de desarrollo

### Requisitos previos

* Java 21 (Oracle JDK u OpenJDK/Temurin)
* Maven 3.9+
* Node.js 20+
* PostgreSQL 15+
* Python 3.10+ (para los scripts de `fabric/`)

### Compilación

```bash
# Backend
mvn clean package -DskipTests

# Frontend
cd frontend && npm install && npm run build
```

### Ejecutando pruebas

```bash
mvn test
```

### Ejecutando localmente

```bash
# Infraestructura
sudo ./installbase.sh

# Aplicación
mvn spring-boot:run
```

### Verificando la instalación

```bash
./scripts/verify-astral.sh
```

## Estructura del proyecto

```
astral-plataform-hci/
├── src/main/java/com/astral/
│   ├── main/              # plano de control
│   │   ├── controller/    # Login, Home, SPA forward, cert download
│   │   ├── security/      # MultiSourceAuthenticationProvider, SecurityConfig,
│   │   │                  # ProxyAuthorizationServer, AstralPrincipal
│   │   └── model/
│   ├── fabric/            # el tejido, en migración hacia la aplicación
│   │   ├── firewall/      # copia de las 14 entidades, API y WebSocket
│   │   ├── network/       # direccionamiento e interfaces
│   │   ├── proxy/         # ACL, auditoría, caché Redis
│   │   └── reconciliation/ # Intent → Validación → Diff → Commit → Rollback
│   └── tools/             # Installer, InstallerFirewall, InstallerProxy,
│                          # NetworkConfig, Uninstaller
├── src/main/resources/    # application.yml + 3 perfiles, db/migration (Flyway),
│                          # data/nameservers.csv
├── frontend/              # Vite + React 18 + PrimeReact
│   └── legacy/            # UI heredada servida por el proxy
├── fabric/                # scripts, servicios y la app heredada
│   ├── DNS/               # Pi-hole
│   ├── firewall/          # app Java aparte (14 entidades, puerto 8040)
│   ├── network-firewall/  # Python
│   ├── samba-ad-dc/       # Samba AD DC (Arch, Debian 13, Fedora)
│   ├── acess-report-system/  # Flask + PostgreSQL
│   └── frontend/          # UI heredada (migrándose a frontend/legacy/)
├── scripts/               # instaladores y verificadores bash
├── etc/astral/            # ad.properties
└── installbase.sh         # instalador de dependencias del sistema
```

## Estándares de código

* Sigue el estilo de código existente (Spring Boot 3.3.5 / Java 21, Python,
  React).
* Usa nombres de variables y métodos significativos.
* Escribe mensajes de commit claros, en portugués, con el formato convencional
  (`tipo(ámbito): descripción`).
* Mantén los métodos pequeños y enfocados en una sola responsabilidad.
* **Comentario > código muerto.** Este proyecto tiene muchos comentarios que
  explican *por qué* algo es así. Preserva ese estándar.

## 📄 Documento vivo

Los cambios de arquitectura, las decisiones y el razonamiento del proyecto se
registran en [`projectupdates.md`](../../projectupdates.md). Si tu PR cambia una
decisión, actualiza ese archivo en el mismo PR.

## Licencia

Al contribuir, aceptas que tus contribuciones se licencien bajo la GNU Affero
General Public License v3.0 (AGPLv3).

## 🌐 Otros idiomas

| Idioma | Documento |
|--------|-----------|
| 🇧🇷 Português (Brasil) | [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) |
| 🇺🇸 English | [CONTRIBUTING.en-US.md](CONTRIBUTING.en-US.md) |
| 🇪🇸 Español | [CONTRIBUTING.es-ES.md](CONTRIBUTING.es-ES.md) |
| 🇫🇷 Français | [CONTRIBUTING.fr-FR.md](CONTRIBUTING.fr-FR.md) |