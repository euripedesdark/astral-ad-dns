# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md"><b>🇧🇷 Português (Brasil)</b></a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo em Rust com Interface Web para Administração e Provisionamento do Samba 4 Active Directory 2016 e BIND 9 Híbrido** — Plataforma completa desenvolvida com base no guia técnico aprofundado de arquitetura corporativa em Linux (Fedora/Rocky Linux) de Euripedes Batista.

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🚀 Novidades da Versão 1.5.0

### 1. Dashboard Operacional & Diagnóstico de Saúde Inequívoco
- **Indicador de Saúde Geral**: Status padronizado e inequívoco (`operational`, `degraded`, `unavailable`, `unknown`) no cabeçalho e na API (`/api/status`).
- **Checklist Operacional Interativo (`/api/checks`)**: Bateria automatizada executada diretamente da interface com medição de latência em milissegundos para:
  - `testparm -s` (Validação sintática do `smb.conf`).
  - `samba-tool dbcheck --cross-ncs` (Integridade de mais de 3.900 objetos do diretório LDB).
  - `chronyc tracking` (Sincronismo de relógio, stratum e offset para Kerberos).
  - `klist` (Validação de tickets Kerberos locais).
  - Localizadores de Serviço DNS SRV (`_ldap._tcp`, `_kerberos._tcp`, `_kerberos._udp`, `_kpasswd._udp`).

### 2. Diagnóstico Profundo de Infraestrutura & Dependências (`/api/diagnostics`)
Aba dedicada com varredura contínua e detalhamento de latência, causas prováveis e ações recomendadas para 10 subsistemas:
- **Motor REST & Console**: Disponibilidade imediata do runtime Axum/Tokio.
- **Serviço Samba Active Directory**: Status e integridade no systemd.
- **Portas de Autenticação**: Sockets LDAP (TCP 389) e Kerberos (TCP 88).
- **Servidor BIND 9 (Hybrid DNS)**: Resolução recursiva isolada em `127.0.0.1:5353`.
- **Resolução de Registros SRV**: Validação de resolução local via `127.0.0.1`.
- **Sincronização de Tempo Chrony NTP**: Alinhamento de relógio e socket assinado (`/var/lib/samba/ntp_signd`).
- **Ferramentas do SO**: Existência e versão dos binários essenciais (`samba-tool`, `named`, `chronyc`, `iptables`, `host`, `klist`).
- **Arquivos & SAM LDB**: Presença e permissões dos arquivos críticos (`smb.conf`, `sam.ldb`, `krb5.conf`).
- **Políticas de Segurança SELinux**: Modo operacional (`Enforcing` / `Permissive` / `Disabled`).
- **Consistência da Base de Dados**: Verificação de integridade estrutural e replicação.

### 3. Gerenciamento Seguro do Firewall (`/api/firewall`)
- **Garantia Estrita de Não Destruição**: Trava tokenizada no backend que bloqueia expressamente comandos com `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` ou `nft flush`.
- **Auditoria de Portas**: Inspeção das 19 portas padrão do Active Directory e BIND 9 com `iptables -C INPUT`.
- **Abertura Segura**: Inserção exclusiva com `iptables -I INPUT 1` e suporte a simulação preventiva (`dry_run`).

### 4. Trilha de Auditoria e Histórico Operacional (`/api/audit`)
- Buffer circular thread-safe em memória (até 500 eventos) registrando identificador de correlação (`evt_...`), operador, tipo de ação, alvo, modo de execução, status e detalhes operacionais.
- Filtros interativos na interface por modo (Todos / Apenas Simulações / Apenas Execuções Reais) e busca textual.

### 5. Modo de Simulação Preventiva (`dry_run`) & Pré-validação
- Disponível no provisionamento (`/api/provision`), usuários (`/api/users`), grupos (`/api/groups`), computadores (`/api/computers`), DNS (`/api/dns`) e BIND 9 (`/api/bind`).
- **Travas Anti-Exclusão**: Bloqueio de exclusão do DC (`DC-ERP`) e de grupos estruturais ("Domain Admins", "Enterprise Admins", etc.).
- **Mascaramento de Credenciais**: Ocultação automática de senhas (`--adminpass=`, `--password=`, `-W`) em todos os logs e trilhas de auditoria.

### 6. Interface Web Moderna & Seletor de Idioma
- Caixa de seleção (`<select>`) no topo do cabeçalho para alternância instantânea entre 4 idiomas com persistência em `localStorage`:
  - 🇧🇷 Português (Brasil)
  - 🇺🇸 English (US)
  - 🇪🇸 Español (España)
  - 🇫🇷 Français (France)
- 100% dos textos, diálogos, tabelas e alertas traduzidos nos 4 idiomas.

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

Acesse no navegador: `http://<SEU_IP>:8095/` (ou através da rota reversa `/ad/` no Nginx).

---

## 📄 Licença e Contribuição

- Licença: **GNU Affero General Public License v3.0** ([`LICENSE.md`](LICENSE.md))
- Diretrizes de Contribuição: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Política de Segurança: [`SECURITY.md`](SECURITY.md)
- Código de Conduta: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
