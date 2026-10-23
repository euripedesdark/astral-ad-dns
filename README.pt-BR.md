# Astral AD & Hybrid DNS

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo em Rust com Interface Web para Administração e Provisionamento do Samba 4 Active Directory 2016 e BIND 9 Híbrido** — Plataforma completa desenvolvida com base no guia técnico aprofundado de arquitetura corporativa em Linux (Fedora/Rocky Linux) de Euripedes Batista.

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🚀 Novidades da Versão 1.4.0

- **Módulo Backend em Rust (Axum 0.8 + Tokio)**:
  - Servidor REST e de arquivos estáticos de alta performance escutando na porta `0.0.0.0:8095`.
  - Serviço systemd nativo `astral-ad-dns.service`.
  - **Garantia de Segurança de Firewall**: Nenhuma regra de firewall existente é limpa ou descartada (`sem flush`). Todas as portas de AD e BIND são verificadas (`iptables -C`) e adicionadas (`iptables -A`) de maneira estritamente não destrutiva.
- **Interface Gráfica Web Moderna (SPA em React 18 + TailwindCSS)**:
  - Painel de controle corporativo com tema escuro (Dark Cyberpunk / Enterprise).
  - Suporte completo a 4 idiomas com troca instantânea: 🇧🇷 Português, 🇺🇸 English, 🇪🇸 Español e 🇫🇷 Français.
- **Painel Geral (Dashboard)**:
  - Níveis funcionais de Floresta e Domínio (Windows Server 2016).
  - Status em tempo real do Samba DC, BIND 9 recursivo (5353) e sincronização NTP Chrony (`gps.nu.ntp.br`).
  - Ferramenta de benchmark diagnóstico comparando latência e respostas entre Samba (53), BIND (5353) e Internet (8.8.8.8).
- **Administração de Usuários e Grupos**:
  - Listagem, criação, alteração de senha, ativação/desativação e exclusão de contas.
  - Gerenciamento de grupos do Active Directory e controle de associação de membros.
- **Gerenciador de DNS & Zonas Reversas**:
  - Gerenciamento de zonas diretas e reversas (`in-addr.arpa`).
  - **Criação Automática de Registros PTR Reversos**: Ao criar um registro A, o sistema calcula a sub-rede reversa, cria a zona se necessário e insere o PTR automaticamente.
- **Gerenciador do BIND 9 Híbrido**:
  - Isolamento estrito: BIND 9 como forwarder recursivo em `127.0.0.1:5353` enquanto o Samba escuta na porta 53 padrão.
  - Edição dinâmica de servidores forwarders com validação via `named-checkconf` e recarga a quente (`rndc / systemctl reload`).
  - Visualizador de logs de consulta (`/var/log/named/query.log`).
- **Saúde, Replicação & SYSVOL**:
  - Monitor de replicação DRS (`samba-tool drs showrepl`).
  - Verificação de integridade do banco LDB (`dbcheck --cross-ncs`) com opção de autocorreção.
  - Verificação e restauração de permissões SYSVOL (`ntacl sysvolcheck` e `sysvolreset`).
  - Gerador do script PowerShell para sincronização de SYSVOL em controladores secundários Windows DC2 (Guia Parte 18.9).
- **Backups Quentes (Online)**:
  - Criação de snapshots completos do Active Directory (`samba-tool domain backup online`).
- **Assistente Interativo de Provisionamento (AD Wizard)**:
  - Passo a passo completo para provisionar um novo controlador DC1 ou ingressar em um domínio existente como DC2.

---

## 🛠️ Instalação e Execução

### Compilação do Backend (Rust)
```bash
cargo build --release --bin astral-ad-dns
```

### Compilação do Frontend (Web GUI)
```bash
cd web
npm install
npm run build
cd ..
```

### Inicialização via systemd
```bash
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service
```

Acesse no navegador: `http://<SEU_IP>:8095/`
