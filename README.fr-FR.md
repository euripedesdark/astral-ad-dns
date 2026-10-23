# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md"><b>🇫🇷 Français (France)</b></a>
</p>

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Module d'Entreprise en Rust avec Interface Web pour l'Administration et le Déploiement de Samba 4 Active Directory 2016 et BIND 9 Hybride** — Développé sur la base du guide technique d'architecture d'entreprise Linux d'Euripedes Batista.

Sous licence **GNU AGPL v3**. Voir [`LICENSE.md`](LICENSE.md).

---

## 🚀 Nouveautés de la Version 1.5.0

### 1. Tableau de Bord Opérationnel et Diagnostic de Santé
- **Indicateur de Santé Global** : Badge sans équivoque (`operational`, `degraded`, `unavailable`, `unknown`) dans l'en-tête et retourné par `/api/status`.
- **Liste de Contrôle Opérationnelle Interactive (`/api/checks`)** : Suite automatisée mesurant la latence en millisecondes pour :
  - `testparm -s` (Validation de la syntaxe de configuration `smb.conf`).
  - `samba-tool dbcheck --cross-ncs` (Intégrité de plus de 3 900 objets d'annuaire LDB).
  - `chronyc tracking` (Synchronisation d'horloge, strate et dérive temporelle pour Kerberos).
  - `klist` (Validation des tickets Kerberos locaux).
  - Localisateurs DNS SRV (`_ldap._tcp`, `_kerberos._tcp`, `_kerberos._udp`, `_kpasswd._udp`).

### 2. Diagnostic Approfondi d'Infrastructure et Dépendances (`/api/diagnostics`)
Onglet dédié avec surveillance continue, latences, causes probables et recommandations concrètes pour 10 sous-systèmes essentiels :
- **Moteur REST & Console Web** : Disponibilité immédiate du runtime Axum/Tokio.
- **Service Samba Active Directory** : Statut et intégrité du démon sous systemd.
- **Ports d'Authentification** : Sockets d'écoute LDAP (TCP 389) et Kerberos (TCP 88).
- **Serveur BIND 9 (Hybrid DNS)** : Résolution récursive isolée sur `127.0.0.1:5353`.
- **Résolution des Enregistrements SRV** : Validation de la résolution DNS locale via `127.0.0.1`.
- **Synchronisation Temporelle Chrony NTP** : Socket signé Samba NTP (`/var/lib/samba/ntp_signd`).
- **Outils Système** : Disponibilité des binaires (`samba-tool`, `named`, `chronyc`, `iptables`, `host`, `klist`).
- **Fichiers & SAM LDB** : Présence et permissions de `smb.conf`, `sam.ldb` et `krb5.conf`.
- **Politiques de Sécurité SELinux** : Mode de fonctionnement (`Enforcing` / `Permissive` / `Disabled`).
- **Consistance de la Base de Données** : Intégrité des partitions et réplication.

### 3. Gestion Sécurisée du Pare-feu (`/api/firewall`)
- **Garantie Stricte de Non-Destruction** : Traitement par jetons rejetant systématiquement toute commande contenant `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` ou `nft flush`.
- **Audit des Ports** : Contrôle continu des 19 ports standard d'Active Directory et BIND 9 avec `iptables -C INPUT`.
- **Ajout Non Destructif** : Insertion exclusive avec `iptables -I INPUT 1` et prise en charge de la simulation préventive (`dry_run`).

### 4. Piste d'Audit et Historique Opérationnel (`/api/audit`)
- Mémoire circulaire (jusqu'à 500 événements) enregistrant l'identifiant de corrélation (`evt_...`), l'opérateur, le type d'action, la cible, le mode, le statut et les détails opérationnels.
- Filtres interactifs par mode (Tous / Simulations Uniquement / Exécutions Réelles Uniquement) et recherche textuelle.

### 5. Mode Simulation Préventive (`dry_run`) & Pré-validation
- Prise en charge complète pour le déploiement (`/api/provision`), utilisateurs (`/api/users`), groupes (`/api/groups`), ordinateurs (`/api/computers`), DNS (`/api/dns`) et BIND 9 (`/api/bind`).
- **Verrous Anti-Suppression** : Protection contre la suppression accidentelle du Contrôleur de Domaine (`DC-ERP`) et des groupes de sécurité fondamentaux ("Domain Admins", etc.).
- **Masquage des Identifiants** : Remplacement automatique des mots de passe sensibles par des astérisques dans tous les journaux.

### 6. Interface Web Moderne avec Sélecteur de Langue
- Menu déroulant (`<select>`) dans l'en-tête supérieur pour basculer instantanément entre 4 langues avec mémorisation dans `localStorage` :
  - 🇧🇷 Português (Brasil)
  - 🇺🇸 English (US)
  - 🇪🇸 Español (España)
  - 🇫🇷 Français (France)
- 100% de l'interface traduite avec exactitude dans les 4 langues.

### 7. Politique d'Accès Unifié et Authentification Multi-Fournisseur
Mise en œuvre de la politique corporative unifiée d'authentification et d'autorisation :
- **Samba Active Directory / OAuth2** : Authentification des utilisateurs et administrateurs de domaine avec mappage des groupes LDAP/Kerberos ou jetons SSO d'`astral-auth-service`.
- **Utilisateur Linux Local (Root / Sudo)** : Accès administrateur système pour les membres des groupes `wheel`/`sudo` ou le compte `root`.
- **Superutilisateur PostgreSQL** : Validation de compte de base de données pour tout rôle disposant de `rolsuper = true` (ex. `postgres`).
- **Jeton Bearer et Cookies de Session** : Prise en charge conjointe des en-têtes `Authorization: Bearer <jwt>` et des cookies `sso_token` / `astral_token`.
- **Points de Terminaison d'Authentification** :
  - `POST /api/auth/login` : Validation des identifiants et émission du jeton JWT.
  - `GET /api/auth/me` : Consultation de l'identité et des privilèges de l'opérateur connecté.
  - `POST /api/auth/logout` : Clôture de session et expiration des cookies.
  - `GET /api/auth/providers` : Liste des mécanismes d'authentification disponibles.
- **Périmètres Préservés** : Déployé transversalement tout en préservant l'autonomie d'`astral-saas-erp` (Java) et de l'interface web IAM d'`auth-service`.

---

## 🛠️ Compilation et Déploiement

### Compilation du Backend (Rust)
```bash
cargo build --release --bin astral-ad-dns
```

### Compilation du Frontend (Interface Web)
```bash
cd web
npm install
npm run build
cd ..
```

### Gestion du Service systemd
```bash
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service
```

Accès navigateur : `http://<VOTRE_IP>:8095/` (ou via le proxy inverse `/ad/`).

---

## 📄 Licence et Contribution

- Licence : **GNU Affero General Public License v3.0** ([`LICENSE.md`](LICENSE.md))
- Guide de Contribution : [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Politique de Sécurité : [`SECURITY.md`](SECURITY.md)
- Code de Conduite : [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
