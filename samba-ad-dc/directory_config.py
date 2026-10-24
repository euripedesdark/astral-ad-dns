#!/usr/bin/python3
"""Run with the Samba distro Python; local system session only, no passwords."""
import argparse
import json
import socket
import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB


def configure(gc=True, repair=True, inspect=False, server=None, username=None, password=None):
    lp = LoadParm()
    lp.load_default()
    db = SamDB(session_info=system_session(), lp=lp)
    schema = db.search(base=db.get_schema_basedn(), scope=ldb.SCOPE_BASE, attrs=['objectVersion'])[0]
    if inspect:
        return {'schema_version': int(schema['objectVersion'][0])}
    root = db.search(base='', scope=ldb.SCOPE_BASE, attrs=['dsServiceName','isGlobalCatalogReady'])[0]
    ntds = ldb.Dn(db, root['dsServiceName'][0].decode())
    if server:
        from samba.credentials import Credentials
        credentials=Credentials();credentials.guess(lp)
        credentials.set_username(username);credentials.set_password(password)
        # The DN was obtained from the local DC, so this changes that DC's GC flag,
        # never the partner's NTDS settings. A RODC sends the write to a writable DC.
        db=SamDB(url='ldap://'+server,credentials=credentials,lp=lp)
        ntds=ldb.Dn(db,str(ntds))
    current = db.search(base=ntds, scope=ldb.SCOPE_BASE, attrs=['options'])[0]
    options = int(current.get('options',[b'0'])[0])
    updated = options | 1 if gc else options & ~1
    if updated != options:
        message = ldb.Message()
        message.dn = ntds
        message['options'] = ldb.MessageElement(str(updated), ldb.FLAG_MOD_REPLACE, 'options')
        db.modify(message)
    repaired = []
    if repair:
        realm = lp.get('realm').lower()
        partitions = db.search(base='CN=Partitions,' + str(db.get_config_basedn()), scope=ldb.SCOPE_ONELEVEL,
            expression='(|(dnsRoot=DomainDnsZones.' + realm + ')(dnsRoot=ForestDnsZones.' + realm + '))', attrs=['msDS-SDReferenceDomain'])
        for partition in partitions:
            if 'msDS-SDReferenceDomain' not in partition:
                message = ldb.Message()
                message.dn = partition.dn
                message['msDS-SDReferenceDomain'] = ldb.MessageElement(str(db.get_default_basedn()), ldb.FLAG_MOD_ADD, 'msDS-SDReferenceDomain')
                db.modify(message)
                repaired.append(str(partition.dn))
    return {'global_catalog_enabled': bool(updated & 1), 'previous_options': options, 'options': updated,
            'dns_partitions_repaired': repaired}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--disable-gc', action='store_true')
    parser.add_argument('--inspect', action='store_true')
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--server')
    parser.add_argument('--username')
    parser.add_argument('--password')
    args = parser.parse_args()
    if args.verify:
        lp=LoadParm(); lp.load_default()
        db=SamDB(session_info=system_session(),lp=lp)
        value=db.search(base='',scope=ldb.SCOPE_BASE,attrs=['isGlobalCatalogReady'])[0]
        ready=value.get('isGlobalCatalogReady',[b'FALSE'])[0].decode().upper() == 'TRUE'
        if ready:
            for port in [3268,3269]:
                with socket.create_connection(('127.0.0.1',port),timeout=3): pass
        print(json.dumps({'ready':ready}))
        raise SystemExit(0 if ready else 1)
    print(json.dumps(configure(not args.disable_gc, inspect=args.inspect,server=args.server,username=args.username,password=args.password)))
