# SYSVOL validation before and after a Samba AD DC join

## Why the wizard used to block

On the secondary host before joining, the user reproduced:

- `smbclient //192.168.2.10/sysvol`: works
- `samba-tool gpo aclcheck -H ldap://192.168.2.10`: SMB connection failure even with explicit IP and with Kerberos disabled
- `samba-tool ntacl sysvolcheck`: fails to open local `sam.ldb`, because the DC has not yet been joined

On the source DC, with domain administrator credentials, `samba-tool gpo aclcheck` succeeds, and local `samba-tool ntacl sysvolcheck` exits 0.

## New ordering

1. Before stopping services or cleaning a prior DC, confirm LDAP/DNS/FSMO using the existing preflight; verify SYSVOL **and** NETLOGON read-only with `smbclient` over signed SMB using the partner IP. Any failure blocks the operation.
2. Continue the backed-up join only after all existing preflights pass. Never use `gpo aclcheck` as an SMB connectivity probe from an unjoined node.
3. After successful DC join, copy SYSVOL from the source. Keep existing local `ntacl sysvolreset` and require `ntacl sysvolcheck` using the new DC's local Samba database.
4. On local ACL validation failure, preserve joined membership and the verified backup; allow reapplying configuration from the GUI instead of rejoining.

The source DC's own GPO consistency should be checked independently on that DC; a remote `smbclient` test alone does not prove remote GPO ACL consistency. This patch does not claim to repair any fault in Samba's GPO SMB client.
