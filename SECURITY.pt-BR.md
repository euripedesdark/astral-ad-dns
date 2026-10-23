# Política de Segurança

A segurança do Astral Platform & HCI é levada a sério. Este projeto é uma
plataforma de infraestrutura que controla rede, firewall e identidade — um
relato bem-feito aqui importa mais do que a maioria.

## Como Reportar

**Não abra issues públicas para vulnerabilidades de segurança.**
Reporte por e-mail: **euripedesdark@gmail.com**

Inclua as seguintes informações:

* Uma descrição da vulnerabilidade
* Passos para reproduzir o problema
* O impacto potencial
* Qualquer correção sugerida (se houver)

## O que esperar

* Reconheceremos seu relato em até 48 horas.
* Investigaremos o problema e forneceremos um prazo de correção.
* Vamos creditar você nas notas de versão (a menos que prefira permanecer
  anônimo).
* Vamos publicar a correção o mais rápido possível e avisar quando ela estiver
  disponível.

## Escopo

Esta política de segurança aplica-se a:

* O código da aplicação do plano de controle
* Os endpoints da API e o proxy de autenticação ATS
* Os scripts de instalação e verificação
* A configuração do sistema e os scripts de provisionamento

## Fora de escopo

* Bibliotecas de terceiros (relate vulnerabilidades aos projetos respectivos)
* O **servidor Graylog**, que é um projeto separado, sob **SSPL-1.0**
* Questões de documentação
* Perguntas gerais sobre boas práticas de segurança

## 🔐 Medidas de segurança

O projeto implementa as seguintes medidas:

* **Autenticação:** Spring Security com fontes múltiplas — Active Directory
  (LDAP/Kerberos) e PostgreSQL — combinadas por
  `MultiSourceAuthenticationProvider`
* **Sessão:** cookie `HttpOnly` e `SameSite=Lax`, expiração de 8 horas,
  `Secure` ativado por `ASTRAL_COOKIE_SECURE`
* **Sessão, não token:** a sessão é stateful, mantida no servidor, com cookie
  `HttpOnly`. `/api/v1/acl/check` aceita um Bearer JWT HS256, mas a validação
  está **desligada por padrão** (`ASTRAL_AUTH_JWT_ENABLED=false`) — o Auth
  Service ainda não emite token, então a sessão é o único caminho que funciona
* **Proxy confiável:** `server.forward-headers-strategy=framework`, porque o ATS
  e o Nginx terminam TLS na frente
* **Segredos:** `auth.env` fica em disco e **fora** do versionamento
* **Banco de dados:** `ddl-auto=validate` + Flyway (`db/migration/`) nos dois
  apps; o legado `fabric/firewall/` (8040) está **aposentado**, mas continua no
  repositório, e o `InstallerFirewall.java` ainda o implanta
* **Isolamento de rede:** a aplicação escuta apenas em loopback (8081/8082); a
  porta pública é 443 via Nginx, com TLS, e 81 responde `301` para 443
* **Verificação:** `scripts/verify-astral.sh` falha de propósito se a
  aplicação estiver exposta fora do loopback
* **Auditoria:** trilha de auditoria e aprovação humana no plano de controle
* **Firewall do sistema:** configurado por
  `scripts/configure-system-firewall.sh`, com `iptables` e `ipset`
* **Antimalware:** ClamAV instalado pelo `installbase.sh`

## Política de divulgação

Seguimos uma política de divulgação coordenada. Pedimos que você:

* Dê tempo razoável para corrigir o problema antes de divulgar publicamente.
* Não explore a vulnerabilidade além do necessário para demonstrá-la.
* Não acesse nem modifique dados pertencentes a outros usuários.

## 🌐 Outros idiomas

| Idioma | Documento |
|--------|-----------|
| 🇧🇷 Português (Brasil) | [SECURITY.pt-BR.md](SECURITY.pt-BR.md) |
| 🇺🇸 English | [SECURITY.en-US.md](SECURITY.en-US.md) |
| 🇪🇸 Español | [SECURITY.es-ES.md](SECURITY.es-ES.md) |
| 🇫🇷 Français | [SECURITY.fr-FR.md](SECURITY.fr-FR.md) |