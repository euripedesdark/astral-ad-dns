# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md"><b>🇫🇷 Français (France)</b></a>
</p>

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Module d'Entreprise en Rust avec Interface Web pour l'Administration, le Provisionnement et la Gestion de Samba 4 Active Directory (Niveau Fonctionnel 2016) et BIND 9 Hybride** — Conçu d'après le guide d'architecture d'entreprise Linux approfondi d'Euripedes Batista.

Distribué sous licence **GNU AGPL v3**. Consultez [`LICENSE.md`](LICENSE.md).

---

## 📋 Table des Matières
1. [Préparation de l'Hôte par Distribution Linux](#1-préparation-de-lhôte-par-distribution-linux)
2. [Installation et Déploiement Automatisé (`deploy_ad_dns.py`)](#2-installation-et-déploiement-automatisé-deploy_ad_dnspy)
3. [Déploiement Manuel Alternatif (Cargo et Systemd)](#3-déploiement-manuel-alternatif-cargo-et-systemd)
4. [Assistant Web de Provisionnement et Topologies](#4-assistant-web-de-provisionnement-et-topologies)
5. [Infrastructure à Clés Publiques (PKI Step-CA et LDAPS)](#5-infrastructure-à-clés-publiques-pki-step-ca-et-ldaps)
6. [Résolution DNS Hybride avec BIND 9 et SELinux](#6-résolution-dns-hybride-avec-bind-9-et-selinux)
7. [Déploiement Propre, Réintégration et Nettoyage des Bases Orphelines](#7-déploiement-propre-réintégration-et-nettoyage-des-bases-orphelines)
8. [Vérification Opérationnelle et Diagnostics](#8-vérification-opérationnelle-et-diagnostics)
9. [Sécurité du Pare-feu et Piste d'Audit](#9-sécurité-du-pare-feu-et-piste-daudit)

---

## 1. Préparation de l'Hôte par Distribution Linux

Avant de lancer l'assistant web pour créer ou intégrer un contrôleur de domaine, préparez les dépôts et paquets système d'entreprise :

### Préparation Rapide Automatisée
Le script `deploy_ad_dns.py` dispose d'une commande dédiée configurant les dépôts officiels vérifiés par GPG et installant tous les binaires nécessaires sans modifier la base Samba locale ni requérir de compilation :

```bash
# Configure les dépôts et installe les paquets sans compiler l'interface web
python3 deploy_ad_dns.py --prepare-ad-only
```

### Spécificités par Distribution

* **RHEL 10 / AlmaLinux 10 / Rocky Linux 10 (EL10) :**
  - Importe la clé officielle `RPM-GPG-KEY-TISSAMBA-10`.
  - Active le dépôt Tranquil IT Samba : `https://samba.tranquil.it/redhat10/samba-4.24/`.
  - Active CRB (`dnf config-manager --set-enabled crb`) et EPEL 10.
  - Installe : `samba`, `samba-dc`, `samba-winbind`, `samba-winbind-clients`, `krb5-workstation`, `ldb-tools`, `bind`, `bind-utils`, `chrony`, `python3-setproctitle`, `policycoreutils-python-utils`.
* **RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (EL9) :**
  - Importe la clé `RPM-GPG-KEY-TISSAMBA-9` et le dépôt `https://samba.tranquil.it/redhat9/samba-4.24/`.
  - Active CRB et EPEL 9.
* **Fedora 44 / 45 :**
  - Utilise les paquets natifs de la distribution (`dnf install -y samba samba-dc bind bind-utils chrony krb5-workstation`).
* **Arch Linux :**
  - Installation via pacman : `pacman -S --needed samba bind chrony krb5`.
* **Debian 12 (Bookworm) / Ubuntu 24.04 LTS :**
  - Installation via apt : `apt-get install -y samba winbind krb5-user bind9 bind9utils chrony ldb-tools`.

---

## 2. Installation et Déploiement Automatisé (`deploy_ad_dns.py`)

Le script `deploy_ad_dns.py` automatise l'ensemble du cycle de vie opérationnel : compilation release ultra-rapide du backend Rust, génération des fichiers statiques du frontend Vite/React, installation dans `/opt/astral-ad-dns/`, activation du service systemd et ouverture sécurisée du port web dans le pare-feu.

```bash
# Déploiement complet en local (sans pousser les modifications vers git)
python3 deploy_ad_dns.py --skip-git

# Déploiement complet avec préparation préalable des paquets système
python3 deploy_ad_dns.py --prepare-ad --skip-git
```

### Ce que Réalise le Déploiement Automatisé :
1. **Compilation du Backend** : Exécute `cargo build --release --bin astral-ad-dns`.
2. **Build de Production du Frontend** : Exécute `npm install` et `npm run build` dans le dossier `web/`.
3. **Installation dans `/opt/astral-ad-dns`** :
   - Binaire copié vers `/opt/astral-ad-dns/astral-ad-dns`.
   - Fichiers statiques déployés dans `/opt/astral-ad-dns/web/dist/`.
   - Scripts d'automatisation installés dans `/opt/astral-ad-dns/samba-ad-dc/`.
   - Lien symbolique créé dans `/usr/local/bin/astral-ad-dns`.
4. **Configuration du Service Systemd** :
   - Génère `/etc/systemd/system/astral-ad-dns.service`.
   - Exécute `systemctl daemon-reload`, active et démarre le service.
5. **Pare-feu Sécurisé** :
   - Vérifie et insère la règle pour le port TCP 8095 dans `iptables` sans réinitialiser les règles existantes.
6. **Contrôle de Santé Automatique** :
   - Teste la réponse HTTP locale sur `http://127.0.0.1:8095/api/auth/providers`.

### Mise à Jour Rapide sur les Nœuds Secondaires (DC2 / RODC)
Pour synchroniser les scripts opérationnels sur les contrôleurs secondaires sans recompiler le binaire Rust :
```bash
cd ~/astral-ad-dns
git pull origin main
sudo cp -r samba-ad-dc/* /opt/astral-ad-dns/samba-ad-dc/
sudo systemctl restart astral-ad-dns.service
```

---

## 3. Déploiement Manuel Alternatif (Cargo et Systemd)

Si vous préférez compiler et installer manuellement les composants :

```bash
# 1. Compiler le Backend en Rust
cargo build --release --bin astral-ad-dns

# 2. Compiler le Frontend React / Vite
cd web
npm install
npm run build
cd ..

# 3. Créer l'Arborescence Système
sudo mkdir -p /opt/astral-ad-dns/web
sudo cp target/release/astral-ad-dns /opt/astral-ad-dns/
sudo cp -r web/dist /opt/astral-ad-dns/web/
sudo cp -r samba-ad-dc /opt/astral-ad-dns/
sudo ln -sf /opt/astral-ad-dns/astral-ad-dns /usr/local/bin/astral-ad-dns

# 4. Configurer et Démarrer le Service Systemd
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service

# 5. Ouvrir dans le Navigateur
# Accédez à http://<IP_DU_SERVEUR>:8095
```

---

## 4. Assistant Web de Provisionnement et Topologies

Ouvrez `http://<IP_DU_SERVEUR>:8095` et cliquez sur **"Assistant de Provisionnement"**. La solution prend en charge quatre topologies majeures :

### 1. Nouveau Domaine Primaire (DC1)
* Création d'une nouvelle forêt Active Directory au niveau fonctionnel **2016**.
* Génération du domaine Kerberos, domaine NetBIOS, Catalogue Global et backend DNS (`SAMBA_INTERNAL`).
* Initialisation optionnelle de l'autorité de certification intégrée Step-CA pour les certificats LDAPS.

### 2. Contrôleur de Domaine Secondaire Réplica Lecture/Écriture (DC2 RW)
* Intégration du serveur comme Domain Controller additionnel dans la forêt existante.
* Réplication bidirectionnelle Multi-Master du répertoire via DRS (Directory Replication Services).
* Synchronisation automatisée du SYSVOL depuis le partenaire avec préservation des ACLs NT.
* Synchronisation horaire stricte et signée pour Kerberos (`ntp_signd`).

### 3. Contrôleur de Domaine en Lecture Seule (RODC)
* Particulièrement adapté aux succursales ou environnements distants à sécurité physique réduite.
* Base de données LDB locale en lecture seule ; les mots de passe des utilisateurs ne sont pas mis en cache par défaut.
* Validation DRS côté partenaire évitant les appels RPC privilégiés susceptibles d'impacter le KDC MIT.

### 4. Serveur Membre du Domaine (MEMBER)
* Serveur Linux intégré au domaine pour une authentification unifiée (Winbind / PAM / NSS).
* N'héberge pas de partitions d'annuaire (`sam.ldb`) et ne consomme pas de ressources de réplication DC.

---

## 5. Infrastructure à Clés Publiques (PKI Step-CA et LDAPS)

Astral AD intègre une gestion complète des certificats numériques avec validation stricte de la chaîne de confiance :

* **Hiérarchie de Certificats à 2 Niveaux** :
  $$\text{Root CA} \longrightarrow \text{Intermediate CA} \longrightarrow \text{Certificat du Contrôleur DC}$$
* **Validation Complète de la Chaîne lors de l'Adhésion** :
  - Sur les nœuds secondaires (DC2 / RODC), l'assistant télécharge automatiquement le certificat intermédiaire officiel via HTTPS (`https://<IP_CA>:9444/intermediates.pem`).
  - OpenSSL valide la chaîne intégrale (`-CAfile trusted-step-root.crt -untrusted intermediates.pem dc.crt`) sans erreur d'émetteur local.
  - Le paramètre `tls cafile` de Samba est configuré avec la chaîne complète concaténée.
* **Renouvellement Automatisé** :
  - Configure le timer systemd `astral-ad-tls-renew.timer` vérifiant et renouvelant les certificats toutes les 15 minutes sans interruption de service.

---

## 6. Résolution DNS Hybride avec BIND 9 et SELinux

La plateforme supprime les conflits entre la résolution interne d'annuaire et la récursion internet externe :

* **Port 53 (UDP/TCP)** : Dédié à `SAMBA_INTERNAL`, faisant autorité sur la zone de domaine et les enregistrements `_msdcs`.
* **Port 5353 (UDP/TCP)** : Instance locale isolée de **BIND 9** configurée exclusivement comme résolveur récursif sur `127.0.0.1:5353`.
* **Intégration SELinux** :
  - L'assistant inspecte les réservations de ports existantes avec `semanage port -l`.
  - Assigne en toute sécurité l'étiquette `dns_port_t` au port 5353 même en présence de règles concurrentes comme `howl_port_t`, maintenant SELinux en mode `Enforcing`.

---

## 7. Déploiement Propre, Réintégration et Nettoyage des Bases Orphelines

Lors de la réutilisation de serveurs ayant hébergé d'anciens contrôleurs de domaine :

* **Nettoyage des Bases Orphelines** :
  - Lorsque l'option de déploiement propre (`clean_existing`, `rejoin` ou `overwrite_existing`) est cochée, le système purge en toute sécurité les bases issues de domaines précédents (par exemple des environnements de test comme `ASTRAL.CELESTE`).
  - Désactive et supprime automatiquement tout service Step-CA hérité appartenant à l'ancien domaine.
* **Instantané de Secours Automatique** :
  - Avant toute suppression, l'assistant génère une sauvegarde chiffrée dans `/var/backups/astral-ad-dns/provision/<ID>/` contenant l'état antérieur de Samba, les règles de pare-feu et les manifestes de restauration.
* **Rétrogradation Sécurisée** :
  - Si le serveur est enregistré auprès du partenaire, exécute `samba-tool domain demote --remove-other-dead-server` pour maintenir la topologie de la forêt intègre.

---

## 8. Vérification Opérationnelle et Diagnostics

Vérifiez l'état du domaine directement depuis la console web (onglets **Checklist** et **Diagnostics**) ou depuis le terminal :

```bash
# 1. Vérifier l'état de la réplication DRS avec le partenaire
sudo samba-tool drs showrepl

# 2. Contrôler l'intégrité structurelle de la base LDB
sudo samba-tool dbcheck --cross-ncs

# 3. Valider la syntaxe du fichier smb.conf
testparm -s

# 4. Interroger les enregistrements DNS de localisation de service (SRV)
dig @127.0.0.1 _ldap._tcp.dc._msdcs.<DOMAINE> SRV +short

# 5. Contrôler la synchronisation horaire pour Kerberos
chronyc tracking

# 6. Vérifier la liaison LDAPS et la chaîne de certificats
openssl s_client -connect 127.0.0.1:636 -showcerts < /dev/null
```

---

## 9. Sécurité du Pare-feu et Piste d'Audit

* **Verrous Anti-Destruction (`/api/firewall`)** :
  - Le moteur Rust rejette toute commande destructive contenant `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` ou `nft flush`.
  - Insertion idempotente via `iptables -I INPUT 1` ciblant uniquement les ports manquants.
* **Piste d'Audit en Mémoire (`/api/audit`)** :
  - Tampon circulaire conservant jusqu'à 500 événements avec horodatage, opérateur, action, état et ID de corrélation.
  - Masquage strict de tous les identifiants et mots de passe dans les journaux d'événements.

---

## 📄 Licence

Ce projet est un logiciel libre sous licence **GNU Affero General Public License v3.0** (`AGPL-3.0`). Consultez [`LICENSE.md`](LICENSE.md) pour les détails complets.
