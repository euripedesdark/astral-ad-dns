# Astral AD & Hybrid DNS

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Samba](https://img.shields.io/badge/Samba-4-green.svg)
![Kerberos](https://img.shields.io/badge/Auth-Kerberos%20%2F%20LDAPS-orange.svg)
![DNS](https://img.shields.io/badge/DNS-Contextual%20Resolver-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)

**Contrôleur de Domaine d'Entreprise Samba 4 et Résolution DNS Hybride** — Module spécialisé de l'écosystème Astral assurant les services d'Active Directory Domain Controller (AD DC), l'authentification centralisée (LDAPS/Kerberos) et la résolution DNS contextuelle haute performance.

Ce projet est distribué sous licence **GNU AGPL v3**. Consultez [`LICENSE.md`](LICENSE.md).

---

## 🎯 Fonctionnalités Clés

- **Samba 4 Active Directory Domain Controller (AD DC)**:
  - Scripts d'approvisionnement entièrement automatisés pour Fedora/RHEL, Debian 13 et Arch Linux.
  - Prise en charge native des certificats SSL/TLS automatiques (Step-CA) et LDAPS sur le port 636.
  - Compatibilité totale avec les postes clients Windows (GPO, RSAT) et les postes Linux via SSSD/PAM.
  - Gestion sécurisée des identifiants d'installation via le fichier isolé `auth.env`.
- **Résolveur DNS Hybride et Contextuel**:
  - Filtrage hors ligne des résolveurs mondiaux fiables (DNSSEC = true, fiabilité >= 0.95).
  - Intégration avec Pi-hole et dnsmasq pour le blocage publicitaire et de télémétrie.
  - Base de données locale de plus de 8 Mo de serveurs DNS internationaux (`nameservers.csv`).

---

## 🛠️ Technologies Utilisées

| Couche | Technologie | Rôle |
|---|---|---|
| **Service d'Annuaire** | Samba 4 AD DC | Émulation Active Directory, LDAP, Kerberos KDC |
| **Sécurité & Identité** | OpenSSL / Step-CA | PKI automatisée, LDAPS (TCP 636), certificats X.509 |
| **Résolution DNS** | BIND9 DLZ / dnsmasq / Pi-hole | DNS faisant autorité et filtrage contextuel |
| **Automatisation Système** | Python 3.12+ | Déploiement sans intervention manuelle |

---

## 💖 Soutenir le Projet

**Virement International (Wise):**
- **Bénéficiaire:** Euripedes Batista de Paiva Junior
- **Routing number (Wire / ACH):** `101019628`
- **Numéro de compte:** `215822927677`
- **Banque:** Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States
- **SWIFT / BIC:** `TRWIUS35XXX`

**PIX (Brésil):** `24adc62c-b073-4587-974d-03fe35f6733f`

---

(c) 2026 Astral AD & Hybrid DNS — **Créé par : Euripedes Batista de Paiva Junior**
