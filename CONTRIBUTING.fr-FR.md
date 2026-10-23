# Contribuer à Astral AD & Hybrid DNS

## Code de Conduite
Ce projet et l’ensemble des contributeurs sont régis par le Code de Conduite.

## Configuration de Développement

### Prérequis
* Rust 1.80+ (cargo, rustc)
* Node.js 20+ & npm 10+
* Samba 4.20+ (samba-dc, samba-client)
* BIND 9 (named)
* Chrony (chronyd)
* Step-CA & Step-CLI (Smallstep PKI)

### Compilation et Exécution

```bash
# Backend Rust
cargo test
cargo build --release

# Frontend React
cd web
npm install
npm run build
```

## Structure du Projet

```
astral-ad-dns/
├── Cargo.toml                 # Métadonnées et dépendances Rust (Axum, Tokio, Libc)
├── Cargo.lock                 # Versions verrouillées des dépendances
├── src/                       # Code source du backend
│   ├── main.rs                # Point d'entrée, serveur Axum sur port 8095
│   ├── config.rs              # Configuration Samba, BIND et chemins
│   ├── auth.rs                # Authentification PAM réelle (root/wheel/sudo) et Samba AD / SSO
│   ├── audit.rs               # Journal d'audit opérationnel structuré
│   ├── system.rs              # Réconciliation iptables et protection resolv.conf
│   ├── system/
│   │   └── firewall_migration.rs # Migrateur firewalld/ufw/nftables vers iptables
│   └── api/                   # Contrôleurs REST unifiés
│       ├── mod.rs             # Routeur principal (/api/*)
│       ├── provision.rs       # Déploiement DC, Join, Schéma 2019, Step-CA PKI
│       ├── dns.rs             # Zones directes, inverses et enregistrements AD DNS
│       ├── bind.rs            # Serveur récursif BIND 9 hybride (port 5353)
│       ├── firewall.rs        # Audit des ports et réconciliation automatique
│       ├── health.rs          # Réplication DRS, dbcheck et SYSVOL
│       ├── users.rs           # Gestion des utilisateurs Active Directory
│       ├── groups.rs          # Gestion des groupes Active Directory
│       ├── computers.rs       # Gestion des ordinateurs du domaine
│       ├── diagnostics.rs     # Diagnostics de santé opérationnelle
│       ├── status.rs          # Surveillance de l'état des services
│       └── terminal.rs        # Console d'administration restreinte
├── web/                       # Interface SPA React 18 + Vite + Tailwind CSS
│   ├── src/
│   │   ├── main.tsx           # Point de montage React
│   │   ├── App.tsx            # Navigation unifiée avec contexte partagé
│   │   ├── i18n.ts            # Dictionnaire multilingue (pt-BR, en-US, es-ES, fr-FR)
│   │   └── components/
│   │       └── DonationModal.tsx # Modal de dons PIX et Wise
│   ├── package.json
│   ├── vite.config.js
│   └── dist/                  # Distribution statique compilée
├── samba-ad-dc/               # Scripts d'automatisation Samba AD DC + Step-CA PKI
│   ├── provision_ad_step_ca.py # Script de déploiement et de renouvellement TLS
│   └── auth.env               # Configuration d'environnement
├── dns/                       # Modèles de configuration BIND hybride
├── nginx/                     # Modèles de proxy inverse Nginx
├── systemd/                   # Unité systemd (astral-ad-dns.service)
└── docs/i18n/                 # Documentation multilingue
```

## Lignes Directrices pour les Pull Requests
1. Créez une branche descriptive à partir de main.
2. Ajoutez des tests unitaires pour les nouvelles fonctionnalités.
3. Assurez-vous que npm run build et cargo test réussissent sans erreur.
4. Soumettez la Pull Request avec un résumé clair.
