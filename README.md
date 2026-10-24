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
