# Existing Step-CA enrollment for secondary domain controllers

The Samba AD directory replicates directory objects, **not** the CA server, Samba TLS private keys or smb.conf. Each DC must receive a separate server key/certificate signed by the existing domain CA.

## Verified reference deployment (13 Nov 2026)

- Domain: `srvcloud.cloud`
- Existing CA: `dc-erp.srvcloud.cloud` (`192.168.2.10`)
- Step CA: `127.0.0.1:9443` (loopback only)
- Auth Service Nginx: `:8443` (**must not be replaced**)
- CA provisioner: `admin` (`JWK`)
- Public CA root SHA256: `1b5804d184dc79c2a3f29b3712109663908884cc94d823029e3fbd9cfded6b94`

## Expose CA API safely on DC1

The file `deploy/nginx/astral-step-ca-proxy.conf.example` is a **manual example**, not a deployed service. Before activating:
1. Confirm the Nginx server certificate and key exist, form a pair, contain `dc-erp.srvcloud.cloud` in SAN, and can be read by Nginx. Confirm the full certificate chain is sent.
2. Confirm the Step CA HTTPS endpoint at `https://127.0.0.1:9443/roots.pem` works; verify its certificate against the trusted root.
3. Check `9444` is not occupied. Install the reviewed example as a new Nginx conf file. Run `sudo nginx -t`, then `sudo systemctl reload nginx`.
4. If INPUT policy is DROP, restrict TCP/9444 to DC2 (`192.168.2.100`) using the existing iptables persistence mechanism. Do **not** blanket-open the port, replace other rules, or disable SELinux; adjust policies only if tests prove they are required.
5. From DC2 verify: `step ca health --ca-url https://dc-erp.srvcloud.cloud:9444 --root /path/to/verified-root-ca.crt`. Endpoint trust must use the pinned root, never `-k` or `--insecure`.

Do not proxy the CA through :8443: that port belongs to the Auth Service. Do not distribute `/etc/step-ca/secrets`, `password.txt`, or CA signing keys.

## Astral wizard on DC2

Choose the DC role, existing domain partner `192.168.2.10`, `Configurar certificado LDAPS e renovacao via Step-CA` and fill:
- CA URL: `https://dc-erp.srvcloud.cloud:9444`
- Fingerprint SHA256: the trusted root fingerprint above, verified out of band
- Provisioner: `admin`
- Provisioner password: enter interactively in the wizard. This is the *JWK provisioner password*, not automatically the Samba administrator password or CA server password.

No CA server is installed or initialized on DC2: only the Step CLI is required. Each DC receives `/etc/samba/tls/dc.crt`, `dc.key` (unique private key), `ca.crt` and a renewal timer.

In case the CA's JWK password cannot be made available securely to the enrollment flow, provisioning should fail safely. Do not copy CA signing keys, and do not silently bypass fingerprint validation.

## Limitations and checks

A configured, **trusted** CA endpoint must be provided for DC2; discovery from untrusted DNS alone is not yet safe. The wizard validates the URL and fingerprint **before** beginning destructive rejoin steps. The CA endpoint must be configured on DC1 before selecting this option.

Validate Step CA issuance/renewal, `openssl s_client -connect vmware.srvcloud.cloud:636 -servername vmware.srvcloud.cloud`, and Samba DRS replication **both ways** after joining. DNS A and SRV records of a multihomed DC must not advertise unreachable interfaces.

This change does not deploy the proxy or alter the running DC1/Step CA/iptables configuration.
