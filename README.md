# Astral AD & Hybrid DNS

🇧🇷 **Português (Brasil):** Clique no link abaixo para ler o README completo em português: [README.pt-BR.md](README.pt-BR.md)

🇺🇸 **English:** Click the link below to read the complete README in English: [README.en-US.md](README.en-US.md)

🇪🇸 **Español:** Haz clic en el siguiente enlace para leer el README completo en español: [README.es-ES.md](README.es-ES.md)

🇫🇷 **Français :** Cliquez sur le lien ci-dessous pour lire le README complet en français : [README.fr-FR.md](README.fr-FR.md)


### Correcao do ingresso DC, RODC e MEMBER

O ingresso usa `--option='netbios name = DC2'`, compatível com `samba-tool domain
join`, em vez de `--netbios-name`. DC e RODC usam SAMBA_INTERNAL; MEMBER nao
recebe backend DNS. O nome NetBIOS do dominio e descoberto pelo Samba, sem impor `-W` derivado
do nome DNS. Para DC/RODC, o preflight consulta os niveis do dominio/floresta e
o padrao local com `testparm`. Configura o DC com o maior entre o nivel exigido
pelo dominio e o padrao local, verifica se a instalacao aceita a configuracao e
persiste o valor em smb.conf. Em dominio 2016, a replica recebe 2016; nao ha
rebaixamento nem elevacao automatica do dominio/floresta. Uma configuracao
aceita nao garante suporte completo a todos os recursos de AD: isso depende
da versao do Samba; o proprio join ainda faz suas verificacoes internas.
O BIND permanece recursivo em 127.0.0.1:5353, sem DLZ.

Antes de alterar o resolver ou limpar residuos, o sistema verifica a sintaxe e
a disponibilidade de `--option`. A limpeza recusa uma base AD local existente
(`sam.ldb`) e exige identificar o parceiro com nome diferente do servidor local.
O IP para os registros DNS e escolhido pela rota ate o parceiro. Atualizar a
console nao inicia Samba/BIND por dependencia da unit; o provisionamento continua
sendo uma acao explicita no assistente.

Para atualizar na pasta do repositorio e repetir o ingresso pelo assistente:

```bash
git pull --ff-only origin main
python3 deploy_ad_dns.py --skip-git
```

Os testes locais validam os comandos e argumentos; a replicacao real deve ser
verificada no dominio apos o ingresso (`samba-tool drs showrepl`).


### DNS do AD e BIND local no ingresso

O assistente exige o IP do DC parceiro. O preflight consulta diretamente
`dig @IP_DO_AD -p 53 _ldap._tcp.dc._msdcs.DOMINIO SRV`; localhost nao e aceito
como parceiro. Durante o ingresso, o resolver consulta somente esse parceiro.
O diagnostico da tela usa IP/dominio informados, sem credenciais embutidas.

`127.0.0.1:5353` e somente o BIND recursivo local opcional. A opcao vem
desmarcada e nao participa da descoberta do AD. O encaminhamento para esse
listener so e ativado depois de validar UDP/TCP. Falha apos o join aparece
como aviso nas etapas, preservando o encaminhamento para o parceiro; nao e
motivo para limpar a base ou repetir o join. Em um novo dominio, uma falha do
BIND opcional mantem um forwarder externo valido em vez de apontar para um
listener local indisponivel.

O teste do BIND aguarda brevemente a inicializacao e, se persistir a falha,
coleta estado e logs da unit antes de restaurar a configuracao anterior.
Os testes locais nao comprovam conectividade com o dominio ou o servico BIND
do servidor de producao.


### BIND ativo, mas sem listener 5353 no Fedora

O configurador verifica conflitos na porta 5353 e o arquivo efetivamente usado
pelo processo named/NAMEDCONF. Se outro processo (por exemplo, mDNS) ocupa a
porta, preserva esse processo e informa o conflito. Nao desativa outros servicos.

Com SELinux ativo, requer `policycoreutils-python-utils` e autoriza TCP/UDP 5353
como `dns_port_t`, sem desabilitar SELinux. A porta fica dedicada ao BIND local;
se a ativacao falhar, restaura os rotulos locais anteriores junto da configuracao.
O diagnostico inclui erros de listener, estado dos sockets e eventos AVC quando
a ferramenta de auditoria esta disponivel. Isso nao substitui a verificacao no
host: servico ativo sozinho nao comprova DNS nem replicacao AD.

Depois de atualizar este helper, aplique novamente pela aba **BIND 9 Recursivo**.
Nao repita o ingresso ou a limpeza da base AD por uma falha dessa etapa opcional.
