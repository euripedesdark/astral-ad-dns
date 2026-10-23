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
