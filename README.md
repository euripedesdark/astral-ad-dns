# Astral AD & Hybrid DNS

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Samba](https://img.shields.io/badge/Samba-4-green.svg)
![Kerberos](https://img.shields.io/badge/Auth-Kerberos%20%2F%20LDAPS-orange.svg)
![DNS](https://img.shields.io/badge/DNS-Contextual%20Resolver-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)

🇧🇷 **Controlador de Domínio Corporativo Samba 4 & Resolução DNS Híbrida** — Módulo especializado do ecossistema Astral responsável pelo serviço de diretório Active Directory (AD DC), autenticação centralizada corporativa (LDAPS/Kerberos) e resolução DNS inteligente com seleção contextual de upstream.

🇺🇸 **Enterprise Samba 4 Active Directory Domain Controller & Hybrid DNS Engine** — Specialized module of the Astral ecosystem providing Active Directory Domain Controller (AD DC) services, centralized identity/authentication (LDAPS/Kerberos), and intelligent DNS resolution with contextual upstream selection.

---

## 🌐 Escolha o seu idioma / Choose your language

| | Idioma / Language | Documentação / Documentation |
|---|---|---|
| 🇧🇷 | **Português (Brasil)** | [README.pt-BR.md](README.pt-BR.md) |
| 🇺🇸 | **English** | [README.en-US.md](README.en-US.md) |
| 🇪🇸 | **Español** | [README.es-ES.md](README.es-ES.md) |
| 🇫🇷 | **Français** | [README.fr-FR.md](README.fr-FR.md) |

🇧🇷 [Português](README.pt-BR.md) · 🇺🇸 [English](README.en-US.md) · 🇪🇸 [Español](README.es-ES.md) · 🇫🇷 [Français](README.fr-FR.md)

---

## 🎯 Principais Recursos / Core Highlights

- **Samba 4 Active Directory Domain Controller (AD DC)**:
  - Provisionamento 100% automatizado para Fedora/RHEL, Debian 13 (Trixie) e Arch Linux.
  - Suporte nativo a LDAPS (porta 636) e certificados TLS automáticos (Step-CA).
  - Compatibilidade total com clientes Windows (GPO, RSAT) e estações Linux integradas via SSSD/PAM.
- **DNS Híbrido & Sensível ao Contexto**:
  - Classificação e seleção offline de provedores DNS mundiais (`nameservers.csv`) com filtragem por DNSSEC e confiabilidade.
  - Integração com Pi-hole e dnsmasq para bloqueio de anúncios e telemetria indesejada.
- **Arquitetura Aberta e Sem Lock-in**:
  - Sem necessidade de licenças proprietárias por CAL de usuário.
  - Configuração parametrizada por `auth.env` seguro e isolado.

---

## 💖 Apoie o Projeto / Support the Project

Astral AD & Hybrid DNS é um projeto Open Source mantido por um único desenvolvedor independente.

Se este projeto ajudou você, sua infraestrutura ou sua empresa, considere apoiar o desenvolvimento:

### Brasil (PIX)

```text
24adc62c-b073-4587-974d-03fe35f6733f
```

### Internacional (Wise)

| Campo | Dados |
|---|---|
| **Beneficiário / Name** | Euripedes Batista de Paiva Junior |
| **Tipo de conta / Account Type** | Checking |
| **Routing Number (Wire & ACH)** | `101019628` |
| **Número da conta / Account Number** | `215822927677` |
| **Banco / Bank Name** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT / BIC** | `TRWIUS35XXX` |

Instruções completas de apoio: [DONATE.md](DONATE.md).

---

## 📄 Licença / License

Distribuído sob a licença **GNU Affero General Public License v3.0 (AGPLv3)**. Consulte [LICENSE.md](LICENSE.md) para o texto legal oficial em inglês ou as traduções correspondentes em `LICENSE.*.md`.

(c) 2026 Astral AD & Hybrid DNS — **Criado por: Euripedes Batista de Paiva Junior**
