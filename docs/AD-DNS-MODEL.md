# AD and hybrid DNS model

The provisioning wizard follows the supplied Fedora Samba script and Samba deployment guide:

- `SAMBA_INTERNAL` owns the AD zones and listens on TCP/UDP 53.
- BIND is a recursive forwarder restricted to `127.0.0.1:5353`.
- Samba forwards external queries to BIND when hybrid DNS is enabled.
- Additional writable DCs and RODCs join the existing domain using `SAMBA_INTERNAL`; they do not provision another forest.
- A member server joins as `MEMBER` without a DC DNS backend.
- The API rejects incompatible DNS backends before modifying the host.
- Existing installations are not converted automatically. Updating the console does not change a running domain's DNS backend.

## Deleting directory objects

Confirmations use an application dialog so they also work inside a portal iframe. Names and distinguished names are preserved when passed to Samba, including spaces, apostrophes, ampersands, and encoded URL characters.

Computers are identified as DCs from `userAccountControl` / `primaryGroupID`, never from their name or the trailing `$`. The local server cannot delete its own computer account.

For a live secondary DC, run `samba-tool domain demote` on that DC first. For a permanently decommissioned DC, the console offers explicit metadata cleanup using `samba-tool domain demote --remove-other-dead-server=NAME`. The API refuses cleanup if LDAP is reachable or the DC owns FSMO roles. A failed reachability probe alone does not prove a DC is decommissioned: the operator must confirm that it will never return to the domain.

OUs are deleted without children by default. Recursive removal requires a separate explicit choice and final confirmation. The system Domain Controllers OU and structural AD groups remain protected. Samba's permission and object-protection errors are returned to the UI.

## Validation

```sh
cargo test --locked
cargo build --locked --bin astral-ad-dns
python3 tests/ad_api_regression.py
npm ci --prefix web
npm run build --prefix web
node tests/confirmation_dialog.cjs
```

The HTTP regression suite uses temporary fake executables, not a real AD. It covers attribute-based DC identification, ordinary computer deletion, local DC protection, explicit dead-DC cleanup, names with special characters, recursive OU opt-in, protected objects, dry-run, and DNS backend rejection. A domain integration test is still needed on a Samba lab to validate replication, real joins, and real demotions.

Command reference: https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html

## Recovery from a domain backup

The wizard now includes **Provisionar / recuperar a partir de backup**, also available in the Backups tab. Import a `.tar.bz2` or `.tar.gz` Samba domain archive (up to 512 MiB), choose it, supply the recovered controller's NetBIOS name/IPv4 or use the current host values, and validate the plan. Recovery requires explicit confirmation that original DCs are stopped/isolated. Replacing an existing local Samba installation requires a separate explicit opt-in.

This is domain disaster recovery, not the way to add a replica to an operational domain. Samba's native restore creates the recovered DC and domain metadata. To add another DC to a live domain, use the DC join workflow.

`ad_operations.py` validates archive members and backup structure, restores with `samba-tool domain backup restore` into a unique staging directory, checks the generated configuration and database, then swaps the complete data tree. It updates generated paths to the final location and retains the previous tree and configuration files. If activation fails, it restores the previous Samba data/configuration and restarts previously active DC services. It never falls back to extracting a failed backup into the live database. IP addresses, interfaces, routes and resolv.conf are not changed by recovery.

The helper must be deployed alongside the binary in `samba-ad-dc/`, as handled by `deploy_ad_dns.py`. Alternatively set `ASTRAL_SCRIPTS_DIR` to the trusted helper directory. Recovery and BIND configuration use a shared operation lock. Imported archives are stored with mode 0600. New administrative actions require a verified administrator session.

Use the updated `nginx/default-astral-ad-dns.conf` snippet for the upload size and long-running recovery/demotion request timeouts.

## Primary and secondary domain controllers

The console identifies the primary from the **PDC emulator FSMO owner**, or an explicit `ASTRAL_PRIMARY_DC` NetBIOS/FQDN setting. The primary cannot be deleted or demoted. DC removal fails closed when the primary cannot be identified. Other FSMO owners must have those roles transferred before removal.

For a running secondary, use **Despromover** and provide domain administrator credentials. For a remote secondary, the console server must already have key-based SSH access with a trusted host key. SSH defaults to `root`; set `ASTRAL_DC_SSH_USER` for another account with passwordless sudo for the operation. Interactive SSH passwords and unknown host keys are not accepted. The helper verifies the target's NetBIOS identity and FSMO roles again on the target before Samba demotion. Domain credentials are sent through stdin, not included in the SSH command or application logs. After successful demotion the AD DC service is stopped; refresh the list to delete any remaining member computer account.

For a permanently offline secondary use metadata cleanup. Never return a controller removed this way to the original domain without rebuilding it.

Recursive OU deletion also checks for critical directory objects or DCs in the subtree and refuses to delete them. Group deletion checks critical/builtin objects before calling Samba. Creation and member management preserve quoted/special-character names.

## Recursive BIND improvements

One shared helper now configures BIND for provisioning, joining, recovery and forwarder updates. It supports `named` on Fedora/Rocky and `bind9` on Debian-style installations. It preserves unrelated top-level zone definitions, replaces the recursive options, validates before installation, retains a configuration copy, and rolls back if configuration, service startup or TCP/UDP recursive queries fail.

The managed options enforce localhost-only queries/recursion/cache, `127.0.0.1:5353`, forward-only mode, DNSSEC auto validation, minimal responses and a 64 MiB cache. Forwarders accept IPv4/IPv6, reject empty/invalid/local-loopback targets and remove duplicates. An existing DLZ configuration is refused rather than silently overwritten. The console shows syntax/listener/loopback diagnostics and benchmarks the actual configured upstreams. Automatic firewall rules no longer expose loopback-only BIND ports 5353 or 953.

Additional validation:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
node tests/ui_workflows.cjs
```

These tests exercise staging, rollback, archive rejection, recursive DNS failures, demotion identity/FSMO guards and the UI with simulated services/DOM. Real Samba/BIND/SSH integration must still be tested in a lab before production recovery.
