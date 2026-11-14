# Gerenciamento PKI independente pela interface web

A área **PKI / Certificados** na navegação do Astral é independente de Novo Domínio, Ingresso, Reingresso, Despromoção e RODC.

## Implementado nesta alteração

- `GET /api/provision/step-ca`: inspeciona localmente o cliente Step CLI, presença de raiz de confiança, certificado LDAPS e CA local, sem modificar serviços.
- `POST /api/provision/step-ca`, action `verify`: instala Step CLI quando necessário, inicia bootstrap da CA remota com SHA256 fixado, verifica o fingerprint da raiz obtida e a saúde da API HTTPS, sem tocar no AD.
- action `trust`: após a mesma validação, instala apenas o certificado público raiz no trust store. Não copia chaves, não cria outra CA e não altera registros de domínio.
- O fluxo usa o helper autenticado do serviço Astral e o lock de operações existente.
- O frontend tem uma aba própria, mensagens de erro e resultados e não precisa acessar o shell.

## Segurança e escopo

O fingerprint precisa ser fornecido por uma fonte confiável separada. A URL exige HTTPS; não use `curl -k` como parte do fluxo automatizado. Nenhuma senha administrativa de AD está envolvida na validação ou instalação da raiz.

**Ainda não implementado por este módulo independente:** solicitação/instalação de certificados LDAPS, renovação sob demanda, criação automática do proxy Nginx no hospedeiro da CA e descoberta de CA. Esses fluxos exigem controles de autorização, backup/reversão e uma migração separada do código de provisionamento existente. Não os apresente como concluídos.

## Testes

`python3 -m unittest discover -s tests -p 'test_pki_management.py' -v`

Essa mudança deve ser compilada e implantada com backend, frontend e os scripts Python da mesma revisão. Nenhuma mudança foi feita no DC1/DC2 pelo GitHub.
