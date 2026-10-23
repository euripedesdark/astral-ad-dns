# Contribuindo para o Astral AD & Hybrid DNS

## Código de Conduta
Este projeto e todos os colaboradores são regidos pelo Código de Conduta. Espera-se respeito e colaboração técnica em todas as interações.

## Configuração de Desenvolvimento

### Pré-requisitos
* Rust 1.80+ (cargo, rustc)
* Node.js 20+ & npm 10+
* Samba 4.20+ (samba-dc, samba-client)
* BIND 9 (named)
* Chrony (chronyd)
* Step-CA & Step-CLI (Smallstep PKI)

### Compilação e Execução

```bash
# Backend Rust
cargo test
cargo build --release

# Frontend React
cd web
npm install
npm run build
```

## Estrutura do Projeto

```
astral-ad-dns/
├── Cargo.toml                 # Metadados e dependências Rust (Axum, Tokio, Libc)
├── Cargo.lock                 # Versões travadas de dependências
├── src/                       # Código-fonte do backend
│   ├── main.rs                # Ponto de entrada, servidor Axum na porta 8095
│   ├── config.rs              # Configurações do serviço e caminhos Samba/BIND
│   ├── auth.rs                # Autenticação PAM real (root/wheel/sudo) e Samba AD / SSO
│   ├── audit.rs               # Registro estruturado de auditoria operacional
│   ├── system.rs              # Reconciliação iptables e proteção resolv.conf
│   ├── system/
│   │   └── firewall_migration.rs # Migrador firewalld/ufw/nftables para iptables
│   └── api/                   # Controladores REST unificados
│       ├── mod.rs             # Roteador principal (/api/*)
│       ├── provision.rs       # Provisionador de DC, Join, Schema 2019, Step-CA PKI
│       ├── dns.rs             # Zonas diretas, reversas e registros DNS do AD
│       ├── bind.rs            # Servidor recursivo BIND 9 híbrido (porta 5353)
│       ├── firewall.rs        # Auditoria de portas e reconciliação automática
│       ├── health.rs          # Replicação DRS, dbcheck e sincronismo SYSVOL
│       ├── users.rs           # Gestão de usuários do Active Directory
│       ├── groups.rs          # Gestão de grupos do Active Directory
│       ├── computers.rs       # Gestão de computadores no domínio
│       ├── diagnostics.rs     # Diagnósticos operacionais
│       ├── status.rs          # Monitoramento de status dos serviços
│       └── terminal.rs        # Console operacional restrito
├── web/                       # Interface Web SPA em React 18 + Vite + Tailwind
│   ├── src/
│   │   ├── main.tsx           # Ponto de entrada React
│   │   ├── App.tsx            # Navegação unificada com abas e contexto compartilhado
│   │   ├── i18n.ts            # Dicionário em 4 idiomas (pt-BR, en-US, es-ES, fr-FR)
│   │   └── components/
│   │       └── DonationModal.tsx # Painel de doações PIX e Wise
│   ├── package.json
│   ├── vite.config.js
│   └── dist/                  # Distribuição estática compilada
├── samba-ad-dc/               # Automações avançadas Samba AD DC + Step-CA PKI
│   ├── provision_ad_step_ca.py # Script completo de provisionamento e renovação TLS
│   └── auth.env               # Parâmetros de ambiente
├── dns/                       # Modelos de configuração BIND híbrido
├── nginx/                     # Modelos de proxy reverso
├── systemd/                   # Unidade systemd (astral-ad-dns.service)
└── docs/i18n/                 # Documentação multilíngue
```

## Diretrizes para Pull Requests
1. Crie uma branch descritiva a partir de main.
2. Escreva testes unitários para novas funcionalidades e endpoints.
3. Garanta que npm run build e cargo test passem sem erros.
4. Submeta o Pull Request com descrição detalhada das modificações.
