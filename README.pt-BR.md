# Astral AD & Hybrid DNS

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Samba](https://img.shields.io/badge/Samba-4-green.svg)
![Kerberos](https://img.shields.io/badge/Auth-Kerberos%20%2F%20LDAPS-orange.svg)
![DNS](https://img.shields.io/badge/DNS-Contextual%20Resolver-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)

**Controlador de Domínio Corporativo Samba 4 & Resolução DNS Híbrida** — Módulo especializado do ecossistema Astral responsável pelo serviço de diretório Active Directory (AD DC), autenticação centralizada corporativa (LDAPS/Kerberos) e resolução DNS inteligente com seleção contextual de upstream.

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🎯 Principais Recursos

- **Samba 4 Active Directory Domain Controller (AD DC)**:
  - Scripts de provisionamento automatizado multi-distribuição (Fedora/RHEL, Debian 13 e Arch Linux).
  - Suporte a provisionamento seguro com certificados SSL/TLS automáticos (Step-CA) e LDAPS na porta 636.
  - Compatibilidade com clientes Windows (GPO, RSAT) e estações Linux integradas via SSSD/Realm.
  - Padronização de credenciais de provisionamento através do arquivo seguro `auth.env`.
- **DNS Sensível a Contexto & Híbrido**:
  - Classificação e seleção offline de provedores DNS confiáveis (DNSSEC = true, confiabilidade >= 0.95).
  - Integração com Pi-hole / dnsmasq para bloqueio de telemetria e anúncios.
  - Base local com mais de 8 MB de servidores DNS mundiais (`nameservers.csv`), garantindo total soberania de dados.
- **Segurança e Conformidade**:
  - Kerberos KRB5 com tickets de autenticação seguros.
  - Isolamento de credenciais locais fora do controle de versão.
  - Integração nativa com `astral-auth-service`, `astral-internet-security` e `astral-traffic-guard`.

---

## 🏗️ Estrutura do Projeto

```
astral-ad-dns/
├── README.md                                 # Hub multilíngue da documentação
├── README.pt-BR.md                           # Documentação em Português
├── README.en-US.md                           # Documentação em Inglês
├── README.es-ES.md                           # Documentação em Espanhol
├── README.fr-FR.md                           # Documentação em Francês
├── LICENSE.md                                # Licença GNU AGPLv3
├── DONATE.md                                 # Dados para doações e apoio
├── samba-ad-dc/                              # Automação e Provisionamento do AD DC
│   ├── auth.env.example                      # Modelo de configuração (REALM, HOSTNAME, SENHA_ADMIN)
│   ├── fedoradc-SSL.py                       # Provisionador para Fedora / RHEL com SSL
│   ├── fedora42dc.py                         # Provisionador para Fedora / RHEL padrão
│   ├── debian13-dc-ssl.py                    # Provisionador para Debian 13 com SSL e AppArmor
│   ├── debian13-dc-no-ssl.py                 # Provisionador para Debian 13 padrão
│   ├── arch-DC-SSL.py                        # Provisionador para Arch Linux com SSL
│   └── arch42dc-no-ssl.py                    # Provisionador para Arch Linux padrão
└── dns/                                      # Resolução DNS e Upstream
    ├── nameservers.csv                       # Base de dados de DNS públicos confiáveis (>8MB)
    └── pihole.py                             # Script de integração e regras de bloqueio
```

---

## 🛠️ Stack Tecnológica

| Camada | Tecnologia | Finalidade |
|---|---|---|
| **Serviço de Diretório** | Samba 4 AD DC | Emulação completa de Active Directory, LDAP, Kerberos KDC |
| **Criptografia e Identidade** | OpenSSL / Step-CA | PKI automática, LDAPS (TCP 636), certificados X.509 |
| **Resolução DNS** | BIND9 DLZ / dnsmasq / Pi-hole | Resolução de nomes autoritativa de domínio e filtragem contextual |
| **Automação do Sistema** | Python 3.12+ | Provisionamento sem interação manual e configuração do host |
| **Sistemas Operacionais** | Linux (Fedora 42, Debian 13, Arch) | Ambientes de produção corporativos auditáveis |

---

## 🚀 Como Utilizar

1. Configure as variáveis de domínio em `samba-ad-dc/auth.env`:
   ```bash
   cp samba-ad-dc/auth.env.example samba-ad-dc/auth.env
   chmod 600 samba-ad-dc/auth.env
   nano samba-ad-dc/auth.env
   ```
2. Execute o provisionador adequado para a sua distribuição:
   ```bash
   # Para Fedora / RHEL com LDAPS e SSL:
   sudo python3 samba-ad-dc/fedoradc-SSL.py

   # Para Debian 13 com LDAPS e SSL:
   sudo python3 samba-ad-dc/debian13-dc-ssl.py
   ```
3. Teste a resolução DNS e a conectividade Kerberos:
   ```bash
   kinit administrator
   klist
   smbclient -L localhost -U%
   ```

---

## 💖 Apoie o Projeto

Astral AD & Hybrid DNS é um projeto Open Source mantido por um único desenvolvedor.

Se este projeto ajudou você, sua empresa ou sua equipe, considere apoiar o desenvolvimento:

**PIX:**
```text
24adc62c-b073-4587-974d-03fe35f6733f
```

### Transferência Internacional (Wise)

| | |
|---|---|
| **Nome** | Euripedes Batista de Paiva Junior |
| **Tipo de conta** | Checking |
| **Routing number (wire e ACH)** | `101019628` |
| **Número da conta** | `215822927677` |
| **Banco** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT/BIC** | `TRWIUS35XXX` |

---

## 📄 Licença

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

(c) 2026 Astral AD & Hybrid DNS — **Criado por: Euripedes Batista de Paiva Junior**
