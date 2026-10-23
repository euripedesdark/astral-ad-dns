# Astral AD & Hybrid DNS

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%20%2B%20Tailwind-blueviolet.svg)

**Module d'Entreprise en Rust avec Interface Web pour l'Administration et le Déploiement de Samba 4 Active Directory 2016 et BIND 9 Hybride** — Développé selon le guide d'architecture d'entreprise Linux d'Euripedes Batista.

Licence **GNU AGPL v3**. Voir [`LICENSE.md`](LICENSE.md).

---

## 🚀 Fonctionnalités (v1.4.0)

- **Moteur Backend en Rust (Axum 0.8 + Tokio)**:
  - Serveur REST performant sur le port `8095`.
  - **Sécurité Pare-feu**: Aucune règle existante n'est purgée. Les ports requis sont inspectés et ajoutés de manière non destructive.
- **Interface Web Moderne (React 18 + TailwindCSS)**:
  - Support multilingue complet : 🇧🇷 PT-BR, 🇺🇸 EN-US, 🇪🇸 ES-ES, 🇫🇷 FR-FR.
- **Gestion Complète d'Active Directory**:
  - Niveau fonctionnel Windows Server 2016 (Domaine & Forêt).
  - Gestion des utilisateurs, groupes et ordinateurs du domaine.
  - Administration DNS avec génération automatique des enregistrements inverses PTR (`in-addr.arpa`).
  - BIND 9 hybride récursif sur `127.0.0.1:5353`.
  - Diagnostic de réplication DRS, vérification de base dbcheck et réinitialisation SYSVOL.
  - Assistant de déploiement interactif pour DC1 et DC2.
