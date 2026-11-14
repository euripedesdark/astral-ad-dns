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


### AD DNS and Local BIND During Domain Join

The wizard requires the IP address of the partner Domain Controller (DC). The pre-flight check queries the partner directly using:
`dig @AD_IP -p 53 _ldap._tcp.dc._msdcs.DOMAIN SRV`. `localhost` is not accepted as a partner. During the join process, the resolver queries only this specified partner. The diagnostic screen uses the provided IP/domain without employing any embedded credentials.

`127.0.0.1:5353` refers exclusively to an optional local recursive BIND instance. This option is unchecked by default and plays no role in AD discovery. Forwarding to this listener is only enabled after UDP/TCP connectivity has been validated. Should a failure occur after the join, it is flagged as a warning within the process steps, while maintaining the existing forwarder to the partner; this does not necessitate clearing the database or repeating the join operation. In the case of a new domain, a failure of the optional BIND instance ensures that a valid external forwarder remains in place, rather than pointing to an unavailable local listener.

The BIND test waits briefly for initialization to complete; if the failure persists, it collects the unit's status and logs before restoring the previous configuration. Note that these local tests do not verify connectivity to the domain itself or to the BIND service running on the production server.


### BIND Active, but No Listener on Port 5353 (Fedora)

The configuration tool checks for conflicts on port 5353 and identifies the specific file currently in use by the `named` process (`NAMEDCONF`). If another process (such as mDNS) is occupying the port, the tool leaves that process intact and reports the conflict; it does not disable other services.

When SELinux is enabled, the `policycoreutils-python-utils` package is required. The tool authorizes TCP/UDP port 5353 by assigning it the `dns_port_t` label, without requiring SELinux to be disabled. The port is then dedicated to the local BIND instance. If activation fails, the previous local labels and configuration are restored.
Diagnostics include listener errors, socket status, and AVC events (when the
audit tool is available). Note that this does not replace verification on the
host itself: an active service alone does not confirm proper DNS or AD replication.

After updating this helper, re-apply the configuration via the **BIND 9 Recursive** tab.
Do not repeat the domain join process or clear the AD database if this optional step fails.


## Web-based provisioning with backup and re-joining

The wizard now offers **Re-join with automatic backup** and **Re-apply
configuration**, featuring a backup history/download option and asynchronous
progress tracking. It handles the installation of dependencies via the
distribution's package manager, and configures iptables, NTP, BIND, the
Global Catalog, and TLS/Step-CA as selected on the screen. If the preferred
port for the new CA is already in use, an alternative port is automatically
assigned, with persistent TCP/UDP rules applied. Nginx routes and the
auth-service are preserved. A target holding FSMO roles will not be cleared.

[Full workflow, comparison with fedoradc-SSL(3).py, and recovery limitations](docs/provisionamento-web.md).
This workflow replaces the previous instructions for manually clearing a domain join.
