# Astral AD & Hybrid DNS

<p align="center">
  <a href="README.pt-BR.md"><b>🇧🇷 Português (Brasil)</b></a> &bull;
  <a href="README.en-US.md">🇺🇸 English</a> &bull;
  <a href="README.es-ES.md">🇪🇸 Español</a> &bull;
  <a href="README.fr-FR.md">🇫🇷 Français</a>
</p>

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![Samba](https://img.shields.io/badge/Samba-4%20AD%20DC%20(2016)-green.svg)
![BIND](https://img.shields.io/badge/BIND-9%20Hybrid%20(5353)-cyan.svg)
![Web GUI](https://img.shields.io/badge/Web%20GUI-React%2018%20%2B%20Tailwind-blueviolet.svg)

**Módulo Corporativo em Rust com Interface Web para Administração, Provisionamento e Gerenciamento do Samba 4 Active Directory (Nível Funcional 2016) e BIND 9 Híbrido** — Desenvolvido com base no guia técnico aprofundado de arquitetura corporativa em Linux de Euripedes Batista.

Distribuído sob licença **GNU AGPL v3**. Consulte [`LICENSE.md`](LICENSE.md).

---

## 📋 Índice
1. [Preparação do Host por Distribuição Linux](#1-preparação-do-host-por-distribuição-linux)
2. [Instalação e Deploy Automatizado (`deploy_ad_dns.py`)](#2-instalação-e-deploy-automatizado-deploy_ad_dnspy)
3. [Deploy Manual Alternativo (Compilação e Serviço)](#3-deploy-manual-alternativo-compilação-e-serviço)
4. [Assistente Web de Provisionamento e Topologias](#4-assistente-web-de-provisionamento-e-topologias)
5. [Infraestrutura de Chaves Públicas (PKI Step-CA e LDAPS)](#5-infraestrutura-de-chaves-públicas-pki-step-ca-e-ldaps)
6. [Resolução DNS Híbrida com BIND 9 e SELinux](#6-resolução-dns-híbrida-com-bind-9-e-selinux)
7. [Deploy Limpo, Reingresso e Limpeza de Bases Órfãs](#7-deploy-limpo-reingresso-e-limpeza-de-bases-órfas)
8. [Verificação Operacional e Diagnósticos](#8-verificação-operacional-e-diagnósticos)
9. [Segurança do Firewall e Trilha de Auditoria](#9-segurança-do-firewall-e-trilha-de-auditoria)

---

## 1. Preparação do Host por Distribuição Linux

Antes de abrir o assistente web para criar ou ingressar em um domínio, prepare os pacotes e repositórios necessários no sistema operacional:

### Preparação Rápida Automatizada
O script `deploy_ad_dns.py` possui um modo dedicado que configura os repositórios GPG corporativos e instala todos os binários essenciais sem alterar o banco de dados do Samba nem exigir compilação manual:

```bash
# Configura repositórios e instala dependências no Linux sem compilar o painel
python3 deploy_ad_dns.py --prepare-ad-only
```

### Detalhamento por Distribuição

* **RHEL 10 / AlmaLinux 10 / Rocky Linux 10 (EL10):**
  - Importa a chave oficial `RPM-GPG-KEY-TISSAMBA-10`.
  - Habilita o repositório Tranquil IT: `https://samba.tranquil.it/redhat10/samba-4.24/`.
  - Habilita CRB (`dnf config-manager --set-enabled crb`) e EPEL 10.
  - Instala: `samba`, `samba-dc`, `samba-winbind`, `samba-winbind-clients`, `krb5-workstation`, `ldb-tools`, `bind`, `bind-utils`, `chrony`, `python3-setproctitle`, `policycoreutils-python-utils`.
* **RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (EL9):**
  - Importa a chave `RPM-GPG-KEY-TISSAMBA-9` e repositório `https://samba.tranquil.it/redhat9/samba-4.24/`.
  - Habilita CRB e EPEL 9.
* **Debian 12 (Bookworm) / Debian 13 (Trixie):**
  - Importa a chave GPG oficial Tranquil IT em `/usr/share/keyrings/tissamba.gpg` (`https://samba.tranquil.it/tissamba-pubkey.gpg`).
  - Habilita o repositório oficial Tranquil IT: `deb [signed-by=/usr/share/keyrings/tissamba.gpg] https://samba.tranquil.it/debian/samba-4.24/ $(lsb_release -cs) main`.
  - Instala os pacotes especializados de Samba AD DC: `samba`, `samba-ad-dc`, `winbind`, `libnss-winbind`, `krb5-user`, `smbclient`, `ldb-tools`, `python3-samba`, `bind9`, `bind9utils`, `chrony`.
* **Fedora 44 / 45:**
  - Utiliza os pacotes oficiais nativos da distribuição (`dnf install -y samba samba-dc bind bind-utils chrony krb5-workstation`). Não requer pacotes de terceiros.
* **Arch Linux:**
  - Instalação oficial via pacman: `pacman -S --needed samba bind chrony krb5`. Não requer pacotes de terceiros.
* **openSUSE Leap 15.x / Tumbleweed / SUSE Linux Enterprise (SLES):**
  - Utiliza os pacotes oficiais nativos da distribuição (`zypper install -y samba samba-ad-dc samba-client samba-winbind krb5-client bind bind-utils chrony`). Não utiliza repositório Tranquil IT.
  - Serviço AD DC: `samba-ad-dc.service` (conflitos desativados: `smb`, `nmb`, `winbind`).
  - Resolução DNS: BIND 9 (`named.service`) com override systemd de permissões (`named.service.d/override.conf` com `ReadWritePaths`) e regras AppArmor para `/var/lib/samba/bind-dns`.
* **Ubuntu 24.04 LTS:**
  - Utiliza os pacotes oficiais nativos da distribuição (Samba 4.19, utiliza os mesmos pacotes que o Debian: `apt-get install -y samba samba-ad-dc winbind libnss-winbind krb5-user smbclient ldb-tools python3-samba bind9 bind9utils chrony`). Não deve utilizar pacotes Tranquil IT.

### Matriz Comparativa: Daemons, Serviços e Segurança

| Recurso / Papel | Fedora (44/45) | openSUSE / SLES | Debian (12/13) | Ubuntu 24.04 LTS | RHEL / EL (9/10) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Serviço AD DC** | `samba.service` (samba-dc) | `samba-ad-dc.service` | `samba-ad-dc.service` | `samba-ad-dc.service` | `samba.service` (samba-dc) |
| **Serviços Membro/File** | `smb`, `nmb`, `winbind` | `smb`, `nmb`, `winbind` | `smbd`, `nmbd`, `winbind` | `smbd`, `nmbd`, `winbind` | `smb`, `nmb`, `winbind` |
| **Gerenciador de Pacotes** | `dnf` | `zypper` | `apt` | `apt` | `dnf` |
| **Repositório AD DC** | Oficial Fedora | Oficial SUSE / OBS | Tranquil IT Samba 4.24 | Oficial Ubuntu (4.19) | Tranquil IT + CRB/EPEL |
| **Pacote Kerberos** | `krb5-workstation` | `krb5-client` | `krb5-user` | `krb5-user` | `krb5-workstation` |
| **Serviço BIND DNS** | `named.service` | `named.service` | `named.service` (`bind9`) | `named.service` (`bind9`) | `named.service` |
| **Diretório BIND** | `/var/named` | `/var/lib/named` | `/var/cache/bind` | `/var/cache/bind` | `/var/named` |
| **Segurança MAC** | SELinux | AppArmor | AppArmor | AppArmor | SELinux |

> ### ❓ Dúvida Frequente: Durante o deploy via Web, o assistente instala os pacotes do Samba?
> **SIM, o assistente possui rotina de autoinstalação de dependências (`install_dependencies`), mas atente-se à sua distribuição:**
> - **Fedora, openSUSE / SUSE, Arch Linux e Ubuntu**: Utilizam os pacotes oficiais diretamente de seus próprios repositórios (sem repositórios de terceiros). O assistente web detecta a ausência e instala tudo automaticamente pelo gerenciador nativo (`dnf`, `zypper`, `pacman`, `apt`).
> - **Debian (12/13) e Enterprise Linux (RHEL 9/10, AlmaLinux 9/10, Rocky Linux 9/10)**: Essas distribuições necessitam dos pacotes especializados de Domain Controller (`samba-ad-dc` / `samba-dc`) fornecidos pelo repositório Tranquil IT. Execute previamente no terminal:
>   ```bash
>   python3 deploy_ad_dns.py --prepare-ad-only
>   ```
>   Esse comando adiciona o repositório corporativo Tranquil IT (com chave GPG) e habilita o CRB/EPEL (no EL). A partir desse momento, tanto o terminal quanto o **assistente web** conseguirão instalar e atualizar todos os pacotes do Samba AD automaticamente!

---

## 2. Instalação e Deploy Automatizado (`deploy_ad_dns.py`)

O script `deploy_ad_dns.py` automatiza todo o ciclo de vida da solução: compilação de alta performance do backend em Rust, empacotamento do frontend Vite, instalação no diretório de produção `/opt/astral-ad-dns/`, criação e ativação da unidade systemd e liberação idempotente da porta web no firewall.

### ⚠️ Execução Sem Pedir Git (`--skip-git`)
Por padrão, para rodar o deploy localmente no servidor **sem que o script solicite autenticação ou tente fazer `git push`** para o repositório remoto, adicione o parâmetro `--skip-git`:

```bash
# 1. Deploy completo local sem interagir com o Git (Recomendado para servidores)
python3 deploy_ad_dns.py --skip-git

# 2. Deploy completo com preparação automática dos pacotes do Samba AD (sem Git)
python3 deploy_ad_dns.py --prepare-ad --skip-git

# 3. Apenas preparar pacotes e repositórios do Samba AD (sem compilar a web e sem Git)
python3 deploy_ad_dns.py --prepare-ad-only
```

> **Por que usar `--skip-git`?** Sem esta flag, o script tenta executar um `git push origin <branch>` no passo final. Em servidores onde as credenciais do Git não estão configuradas (ou em deploys manuais), o comando pode solicitar usuário/senha ou travar. A flag `--skip-git` pula essa etapa e garante um deploy 100% local, rápido e sem interrupções.

### O que o Deploy Automatizado Executa:
1. **Compilação do Backend**: Compila `cargo build --release --bin astral-ad-dns` com binário otimizado.
2. **Build de Produção do Frontend**: Executa `npm install` e `npm run build` na pasta `web/`.
3. **Instalação em `/opt/astral-ad-dns`**:
   - Binário copiado para `/opt/astral-ad-dns/astral-ad-dns`.
   - Frontend estático sincronizado em `/opt/astral-ad-dns/web/dist/`.
   - Scripts de automação Samba AD instalados em `/opt/astral-ad-dns/samba-ad-dc/`.
   - Link simbólico criado em `/usr/local/bin/astral-ad-dns`.
4. **Criação do Serviço Systemd**:
   - Cria `/etc/systemd/system/astral-ad-dns.service`.
   - Executa `systemctl daemon-reload`, habilita e inicia o serviço.
5. **Firewall Seguro**:
   - Garante que a porta TCP 8095 esteja aberta no `iptables` sem efetuar flush de regras existentes.
6. **Health Check Automático**:
   - Testa a resposta HTTP local (`http://127.0.0.1:8095/api/auth/providers`).

### Atualização Rápida de Nós Secundários (DC2 / RODC)
Para atualizar apenas os scripts operacionais sem recompilar o binário em máquinas secundárias já instaladas:
```bash
cd ~/astral-ad-dns
git pull origin main
sudo cp -r samba-ad-dc/* /opt/astral-ad-dns/samba-ad-dc/
sudo systemctl restart astral-ad-dns.service
```

---

## 3. Deploy Manual Alternativo (Compilação e Serviço)

Caso deseje realizar as etapas de compilação e deploy de forma manual:

```bash
# 1. Compilar o Backend em Rust
cargo build --release --bin astral-ad-dns

# 2. Compilar o Frontend React / Vite
cd web
npm install
npm run build
cd ..

# 3. Criar a estrutura do sistema
sudo mkdir -p /opt/astral-ad-dns/web
sudo cp target/release/astral-ad-dns /opt/astral-ad-dns/
sudo cp -r web/dist /opt/astral-ad-dns/web/
sudo cp -r samba-ad-dc /opt/astral-ad-dns/
sudo ln -sf /opt/astral-ad-dns/astral-ad-dns /usr/local/bin/astral-ad-dns

# 4. Configurar e Iniciar a Unidade Systemd
sudo cp systemd/astral-ad-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now astral-ad-dns.service

# 5. Acessar no Navegador
# Abra http://<IP_DO_SERVIDOR>:8095
```

---

## 4. Assistente Web de Provisionamento e Topologias

Acesse `http://<IP_DO_SERVIDOR>:8095` e clique em **"Assistente de Provisionamento"**. O assistente suporta quatro topologias corporativas:

### 1. Novo Domínio Primário (DC1)
* Criação de uma floresta Active Directory nova com nível funcional **2016**.
* Geração do domínio Kerberos/NetBIOS, catálogo global e backend DNS interno (`SAMBA_INTERNAL`).
* Opcionalmente inicializa a autoridade certificadora Step-CA integrada para emissão de certificados LDAPS.

### 2. Controlador Secundário Réplica Leitura/Escrita (DC2 RW)
* Ingresso do servidor como Domain Controller adicional na floresta existente.
* Replicação bidirecional Multi-Master de diretório via DRS (Directory Replication Services).
* Sincronização automatizada do SYSVOL a partir do parceiro com preservação de ACLs NT.
* Sincronismo estrito de tempo NTP assinado para Kerberos (`ntp_signd`).

### 3. Controlador de Domínio Somente-Leitura (RODC)
* Especial para filiais, escritórios remotos ou perímetros de rede com menor nível de confiança física.
* Banco de dados local LDB gravado como somente-leitura; senhas não são cacheadas por padrão.
* Validação do DRS no parceiro sem efetuar chamadas RPC privilegiadas que colidam com KDC MIT.

### 4. Servidor Membro do Domínio (MEMBER)
* Servidor Linux integrado ao domínio para autenticação unificada (Winbind / PAM / NSS).
* Não armazena base de dados de diretório (`sam.ldb`) nem consome recursos de Domain Controller.

---

## 5. Infraestrutura de Chaves Públicas (PKI Step-CA e LDAPS)

O Astral AD implementa suporte completo a certificados digitais com validação estrita da cadeia de confiança:

* **Arquitetura Hierárquica em 2 Níveis**:
  $$\text{Root CA} \longrightarrow \text{Intermediate CA} \longrightarrow \text{Certificado do Servidor DC}$$
* **Validação de Cadeia Completa no Ingresso**:
  - Em nós secundários (DC2 / RODC), o assistente obtém automaticamente o certificado intermediário oficial da CA via HTTPS (`https://<IP_CA>:9444/intermediates.pem`).
  - O OpenSSL valida a cadeia completa (`-CAfile trusted-step-root.crt -untrusted intermediates.pem dc.crt`) sem falhas de emissor local (error 20 depth 0).
  - O arquivo `ca.crt` do Samba é configurado com a cadeia completa concatenada.
* **Renovação Automática de Certificados**:
  - Configuração do timer do systemd `astral-ad-tls-renew.timer` que verifica e renova o certificado a cada 15 minutos sem interrupção de serviço.

---

## 6. Resolução DNS Híbrida com BIND 9 e SELinux

A plataforma resolve o conflito clássico entre a resolução interna do Active Directory e a navegação recursiva de internet:

* **Porta 53 (UDP/TCP)**: Exclusiva para o `SAMBA_INTERNAL` do Samba AD DC, atendendo à zona de domínio e registros especiais `_msdcs`.
* **Porta 5353 (UDP/TCP)**: Instância local isolada do **BIND 9** configurada exclusivamente como resolvedor recursivo em `127.0.0.1:5353`.
* **Integração SELinux**:
  - O assistente inspeciona políticas prévias com `semanage port -l`.
  - Garante a atribuição do rótulo `dns_port_t` na porta 5353 mesmo na coexistência com serviços como `howl_port_t`, sem exigir o desligamento do SELinux (`Enforcing` preservado).

---

## 7. Deploy Limpo, Reingresso e Limpeza de Bases Órfãs

Ao reaproveitar servidores previamente utilizados como controladores de domínio ou que possuam bases legadas:

* **Limpeza de Bases Órfãs**:
  - Quando a opção de deploy limpo (`clean_existing` ou `rejoin` ou `overwrite_existing`) está ativa, o sistema autoriza a limpeza segura de bases pertencentes a domínios anteriores (por exemplo, bases de testes como `ASTRAL.CELESTE`).
  - Desativa e remove automaticamente qualquer serviço legado de Step-CA que pertencesse ao domínio antigo.
* **Backup de Segurança Automático**:
  - Antes de qualquer remoção de arquivos, o assistente gera um snapshot criptográfico em `/var/backups/astral-ad-dns/provision/<ID>/` contendo o estado anterior do Samba, regras de firewall e manifestos de rollback.
* **Despromoção Segura**:
  - Se o servidor estiver ativo no parceiro, executa `samba-tool domain demote --remove-other-dead-server` para não deixar metadados corrompidos na topologia da floresta.

---

## 8. Verificação Operacional e Diagnósticos

Após a conclusão do deploy, você pode validar a integridade do domínio diretamente pela interface web (aba **Checklist** e aba **Diagnósticos**) ou pelo terminal:

```bash
# 1. Verificar o status e a replicação DRS com o parceiro
sudo samba-tool drs showrepl

# 2. Validar a integridade estrutural do banco LDB
sudo samba-tool dbcheck --cross-ncs

# 3. Testar a sintaxe do arquivo de configuração do Samba
testparm -s

# 4. Verificar a resolução dos localizadores de serviço DNS (SRV)
dig @127.0.0.1 _ldap._tcp.dc._msdcs.<DOMINIO> SRV +short

# 5. Conferir a sincronização de tempo para o Kerberos
chronyc tracking

# 6. Checar o status dos certificados LDAPS
openssl s_client -connect 127.0.0.1:636 -showcerts < /dev/null
```

---

## 9. Segurança do Firewall e Trilha de Auditoria

* **Bloqueio Anti-Destruição (`/api/firewall`)**:
  - O motor Rust rejeita terminantemente comandos destrutivos contendo `-F`, `--flush`, `-X`, `-Z`, `-D`, `-P`, `-R` ou `nft flush`.
  - Adição idempotente de regras com `iptables -I INPUT 1` apenas para as portas que não estejam abertas.
* **Trilha de Auditoria em Memória (`/api/audit`)**:
  - Buffer circular registrando até 500 eventos administrativos com data/hora, operador, tipo de evento, status e ID de correlação.
  - Ofuscação estrita de credenciais em todos os logs e eventos de sistema.

---

## 📄 Licença

Este projeto é software livre licenciado sob a **GNU Affero General Public License v3.0** (`AGPL-3.0`). Consulte [`LICENSE.md`](LICENSE.md) para o texto integral da licença.
