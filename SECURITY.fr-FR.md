# Politique de Sécurité

Nous prenons la sécurité d'Astral Platform & HCI au sérieux. Ce projet est une
plateforme d'infrastructure qui contrôle le réseau, le pare-feu et l'identité —
un signalement bien fait compte plus que la plupart.

## Comment signaler

**N'ouvrez pas de ticket public pour une faille de sécurité.**
Écrivez-nous à : **euripedesdark@gmail.com**

Incluez les informations suivantes :

* Une description de la faille
* Les étapes pour reproduire le problème
* L'impact potentiel
* Toute correction suggérée (le cas échéant)

## À quoi s'attendre

* Nous accusons réception de votre signalement dans les 48 heures.
* Nous étudions le problème et vous proposerons un délai de correction.
* Nous vous créditerons dans les notes de version (sauf si vous préférez rester
  anonyme).
* Nous publierons le correctif dès que possible et vous préviendrons dès qu'il
  sera disponible.

## À qui s'applique

Cette politique de sécurité s'applique à :

* Le code de l'application du plan de contrôle
* Les points d'entrée de l'API et le proxy d'authentification ATS
* Les scripts d'installation et de vérification
* La configuration système et les scripts de provisionnement

## Hors périmètre

* Les bibliothèques tierces (signalez les failles aux projets respectifs)
* Le **serveur Graylog**, qui est un projet séparé, sous **SSPL-1.0**
* Les problèmes de documentation
* Les questions générales sur les bonnes pratiques de sécurité

## 🔐 Mesures de sécurité

Le projet met en œuvre les mesures suivantes :

* **Authentification :** Spring Security avec plusieurs sources — Active
  Directory (LDAP/Kerberos) et PostgreSQL — combinées par
  `MultiSourceAuthenticationProvider`
* **Session :** cookie `HttpOnly` et `SameSite=Lax`, expiration de 8 heures,
  `Secure` activé via `ASTRAL_COOKIE_SECURE`
* **Session, pas jeton :** la session est avec état et conservée sur le
  serveur, avec un cookie `HttpOnly`. `/api/v1/acl/check` accepte un Bearer JWT
  HS256, mais la validation est **désactivée par défaut**
  (`ASTRAL_AUTH_JWT_ENABLED=false`) — le Auth Service n'émet pas encore de
  jetons, donc la session est le seul chemin qui fonctionne
* **Proxy de confiance :** `server.forward-headers-strategy=framework`, car ATS
  et Nginx terminent le TLS en amont
* **Secrets :** `auth.env` reste sur disque et **hors** gestion de versions
* **Base de données :** `ddl-auto=validate` + Flyway (`db/migration/`) dans les
  deux applications ; l'héritée `fabric/firewall/` (8040) est **retirée** mais
  toujours dans le dépôt, et `InstallerFirewall.java` la déploie toujours
* **Isolation réseau :** l'application n'écoute que sur la boucle locale
  (8081/8082) ; le port public est 443 via Nginx, avec TLS, et 81 répond `301`
  vers 443
* **Vérification :** `scripts/verify-astral.sh` échoue volontairement si
  l'application est exposée hors de la boucle locale
* **Audit :** piste d'audit et approbation humaine dans le plan de contrôle
* **Pare-feu système :** configuré par `scripts/configure-system-firewall.sh`,
  avec `iptables` et `ipset`
* **Anti-malware :** ClamAV installé par `installbase.sh`

## Politique de divulgation

Nous suivons une politique de divulgation coordonnée. Nous vous demandons de :

* Nous laisser un délai raisonnable pour corriger le problème avant toute
  divulgation publique.
* Ne pas exploiter la faille au-delà de ce qui est nécessaire pour la
  démontrer.
* Ne pas accéder ni modifier les données appartenant à d'autres utilisateurs.

## 🌐 Autres langues

| Langue | Document |
|--------|----------|
| 🇧🇷 Português (Brasil) | [SECURITY.pt-BR.md](SECURITY.pt-BR.md) |
| 🇺🇸 English | [SECURITY.en-US.md](SECURITY.en-US.md) |
| 🇪🇸 Español | [SECURITY.es-ES.md](SECURITY.es-ES.md) |
| 🇫🇷 Français | [SECURITY.fr-FR.md](SECURITY.fr-FR.md) |