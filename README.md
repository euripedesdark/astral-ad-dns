# Astral AD & Hybrid DNS

🇧🇷 **Português (Brasil):** Clique no link abaixo para ler o README completo em português: [README.pt-BR.md](README.pt-BR.md)

🇺🇸 **English:** Click the link below to read the complete README in English: [README.en-US.md](README.en-US.md)

🇪🇸 **Español:** Haz clic en el siguiente enlace para leer el README completo en español: [README.es-ES.md](README.es-ES.md)

🇫🇷 **Français :** Cliquez sur le lien ci-dessous pour lire le README complet en français : [README.fr-FR.md](README.fr-FR.md)

### Fix for DC, RODC, and MEMBER domain join

The join process now uses `--option='netbios name = DC2'`—compatible with `samba-tool domain join`—instead of `--netbios-name`. DCs and RODCs use `SAMBA_INTERNAL`, while MEMBER servers do not receive a DNS backend. The domain's NetBIOS name is automatically discovered by Samba, eliminating the need to derive it from the DNS name via the `-W` flag. For DCs/RODCs, a preflight check queries the domain/forest functional levels and the local default settings (via `testparm`). It then configures the DC using the higher of the two values—the domain-required level or the local default—verifies that the installation supports this configuration, and persists the setting in `smb.conf`. In a 2016-level domain, a replica will be set to the 2016 level; there is no automatic domain/forest functional level demotion or elevation. Note that a successful configuration does not guarantee full support for all AD features—this depends on the specific Samba version, and the join process itself performs its own internal validation checks. BIND remains configured as a recursive resolver on `127.0.0.1:5353`, without using DLZ.

Before modifying the resolver or clearing existing data, the system validates the syntax and the availability of the `--option` flag. The cleanup routine will reject an existing local AD database (`sam.ldb`) and requires that the replication partner be identified by a name different from that of the local server. The IP address used for DNS records is determined based on the network route to the partner. Updating the console does not automatically start Samba/BIND, as these are handled via unit dependencies; provisioning remains an explicit action within the wizard.

To update from the repository directory and re-run the join process via the wizard:

```bash
git pull --ff-only origin main
python3 deploy_ad_dns.py --skip-git
```

Local tests validate the commands and arguments; Actual replication should be
verified within the domain after joining (`samba-tool drs showrepl`).

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
