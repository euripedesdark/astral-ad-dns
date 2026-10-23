# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md">🇧🇷 Português</a> &bull;
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

## 🌐 Documentação em 4 Idiomas / Multilingual Documentation

| Idioma / Language | Documento / Document |
| :--- | :--- |
| 🇧🇷 **Português (Brasil)** | [`README.pt-BR.md`](README.pt-BR.md) |
| 🇺🇸 **English (US)** | [`README.en-US.md`](README.en-US.md) |
| 🇪🇸 **Español (España)** | [`README.es-ES.md`](README.es-ES.md) |
| 🇫🇷 **Français (France)** | [`README.fr-FR.md`](README.fr-FR.md) |

---

## 🚀 Novidades da Versão 1.5.0

### 1. Dashboard Operacional & Diagnóstico de Saúde Inequívoco
- **Indicador de Saúde Geral**: Status padronizado e inequívoco (`operational`, `degraded`, `unavailable`, `unknown`) no cabeçalho e na API (`/api/status`).
- **Checklist Operacional Interativo (`/api/checks`)**: Bateria automatizada executada diretamente da interface com medição de latência em milissegundos para `testparm`, `samba-tool dbcheck`, `chronyc tracking`, `klist` e registros SRV DNS.

### 2. Diagnóstico Profundo de Infraestrutura & Dependências (`/api/diagnostics`)
Aba dedicada com varredura contínua e detalhamento de latência, causas prováveis e ações recomendadas para 10 subsistemas (API, Samba AD, LDAP/Kerberos, BIND 9, SRV, NTP, Ferramentas SO, Arquivos de configuração, SELinux e consistência LDB).

### 3. Gerenciamento Seguro do Firewall (`/api/firewall`)
- **Garantia Estrita de Não Destruição**: Trava tokenizada no backend que bloqueia expressamente comandos com `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` ou `nft flush`.
- **Auditoria de Portas**: Inspeção das 19 portas padrão do Active Directory e BIND 9 com `iptables -C INPUT`.
- **Abertura Segura**: Inserção exclusiva com `iptables -I INPUT 1` e suporte a simulação preventiva (`dry_run`).

### 4. Trilha de Auditoria e Histórico Operacional (`/api/audit`)
Buffer circular thread-safe em memória (até 500 eventos) registrando identificador de correlação (`evt_...`), operador, tipo de ação, alvo, modo de execução, status e detalhes operacionais.

### 5. Modo de Simulação Preventiva (`dry_run`) & Pré-validação
Suporte a simulação no provisionamento, usuários, grupos, computadores, DNS e BIND 9, com bloqueio contra exclusão do controlador de domínio principal (`DC-ERP`) e mascaramento automático de credenciais.

### 6. Interface Web Moderna & Seletor de Idioma
Caixa de seleção (`<select>`) no topo do cabeçalho para alternância instantânea entre os 4 idiomas (🇧🇷 Português, 🇺🇸 English, 🇪🇸 Español, 🇫🇷 Français) com persistência em `localStorage`.

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
