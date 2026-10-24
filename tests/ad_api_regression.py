#!/usr/bin/env python3
"""HTTP regressions with Samba/system commands replaced by isolated fakes.
Run: cargo build --locked --bin astral-ad-dns && python3 tests/ad_api_regression.py
Never talks to an AD or changes the host's firewall/services.
"""
import json
import base64
import hashlib
import hmac
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FAKE = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['AD_TEST_LOG'], 'a') as f:
    f.write(json.dumps([name, *args]) + '\\n')
if name == 'testparm':
    print('/mock/private' if any('private dir' in arg for arg in args) else 'PRIMARY')
elif name == 'hostname':
    print('primary' if args == ['-s'] else '192.0.2.10')
elif name == 'systemctl':
    sys.exit(1)
elif name == 'samba-tool':
    if args == ['computer', 'list']:
        print('DC-DESKTOP$\\nSECONDARY$\\nPRIMARY$\\nREADONLY$')
    elif args[:2] == ['computer', 'show']:
        dc = args[2].rstrip('$') in ['SECONDARY', 'PRIMARY', 'READONLY']
        readonly = args[2].rstrip('$') == 'READONLY'
        print('sAMAccountName: ' + args[2].rstrip('$') + '$')
        print('userAccountControl: ' + ('67112960' if readonly else '532480' if dc else '4096'))
        print('primaryGroupID: ' + ('521' if readonly else '516' if dc else '515'))
        print('dNSHostName: 127.0.0.1')
    elif args == ['fsmo', 'show']:
        print('PdcEmulationMasterRole owner: CN=NTDS Settings,CN=PRIMARY,CN=Servers')
        print('SchemaMasterRole owner: CN=NTDS Settings,CN=' + Path(os.environ['AD_TEST_LOG']).with_name('fsmo').read_text() + ',CN=Servers')
    elif args[:2] == ['ou', 'list']:
        print("OU=R&D's Lab,DC=example,DC=test")
    elif args[:2] == ['ou', 'delete'] and '--force-subtree-delete' not in args:
        print('OU is not empty', file=sys.stderr)
        sys.exit(1)
    else:
        print('Success')
'''


def main():
    with tempfile.TemporaryDirectory(prefix='astral-ad-test-') as temp:
        tmp = Path(temp)
        executable = tmp / 'fake'
        executable.write_text(FAKE)
        executable.chmod(0o755)
        (tmp / 'fsmo').write_text('PRIMARY')
        for name in ['testparm', 'hostname', 'systemctl', 'samba-tool', 'iptables',
                     'ip6tables', 'ss', 'firewall-cmd', 'nft', 'ldbsearch']:
            (tmp / name).symlink_to(executable)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, PATH=str(tmp) + os.pathsep + os.environ['PATH'],
                   AUTH_TOKEN_SECRET='astral-regression-only-secret', ASTRAL_PRIMARY_DC='SECONDARY',
                   AD_TEST_LOG=str(tmp / 'calls.jsonl'), ASTRAL_BIND_ADDR=f'127.0.0.1:{port}',
                   ASTRAL_WEB_DIST=str(ROOT / 'web/dist'))
        helpers = tmp / 'helpers'
        helpers.mkdir()
        (helpers / 'ad_operations.py').write_text("""import json, sys
request = json.load(sys.stdin)
action = request.get('action')
if action == 'overview': data = {'snapshots': [], 'reports': []}
elif action == 'html': data = {'html': '<!doctype html><html><body>Forensic test report</body></html>'}
elif action == 'report': data = {'id': request['report_id']}
else: data = {'snapshot_id': 'snp_' + 'a' * 32, 'report_id': 'rep_' + 'b' * 32, 'status': 'partial', 'summary': {}}
print(json.dumps({'success': True, 'data': data}))
""")
        env['ASTRAL_SCRIPTS_DIR'] = str(helpers)
        proc = subprocess.Popen([str(ROOT / 'target/debug/astral-ad-dns')], cwd=ROOT,
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def token(admin=True):
            encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
            parts = [encode({'alg': 'HS256', 'typ': 'JWT'}), encode({'sub': 'tester', 'username': 'tester', 'provider': 'AD', 'is_admin': admin, 'has_wheel': admin, 'exp': int(time.time()) + 300})]
            signature = base64.urlsafe_b64encode(hmac.new(b'astral-regression-only-secret', b'.'.join(parts), hashlib.sha256).digest()).rstrip(b'=')
            return b'.'.join(parts + [signature]).decode()
        def request(method, path, payload=None, auth=True):
            req = urllib.request.Request(f'http://127.0.0.1:{port}' + path,
                data=json.dumps(payload).encode() if payload is not None else None,
                headers={'Content-Type': 'application/json', **({'Authorization': 'Bearer ' + token()} if auth else {})}, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            return response.status, json.load(response)
        def calls():
            return [json.loads(line) for line in (tmp / 'calls.jsonl').read_text().splitlines()]
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError('Test server exited')
                try:
                    status, data = request('GET', '/api/computers')
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            assert status == 200, data
            assert data['data'][0]['is_dc'] is False, data
            assert data['data'][1]['is_dc'] is True, data
            assert data['data'][2]['is_local'] is True, data
            assert data['data'][2]['is_primary'] is True, data
            assert data['data'][3]['is_rodc'] is True, data
            for target, action in [('PRIMARY', 'promote_primary'), ('READONLY', 'promote_primary'), ('SECONDARY', 'promote_writable')]:
                assert request('POST', '/api/computers/' + target + '/transition', {'action': action, 'admin_username': 'test', 'admin_password': 'test'})[0] == 400
            assert request('POST', '/api/computers/SECONDARY/transition', {'action': 'promote_primary', 'admin_username': 'test', 'admin_password': 'test'}, auth=False)[0] == 401
            assert request('DELETE', '/api/computers/DC-DESKTOP%24', auth=False)[0] == 401
            assert request('DELETE', '/api/computers/DC-DESKTOP%24')[0] == 200
            assert ['samba-tool', 'computer', 'delete', 'DC-DESKTOP'] in calls()
            assert request('DELETE', '/api/computers/PRIMARY%24')[0] == 403
            assert request('POST', '/api/computers/PRIMARY%24/demote', {'admin_username': 'test', 'admin_password': 'test'})[0] == 400
            assert request('DELETE', '/api/computers/SECONDARY%24')[0] == 409
            (tmp / 'fsmo').write_text('SECONDARY')
            assert request('DELETE', '/api/computers/SECONDARY%24?remove_dead_dc=true')[0] == 409
            (tmp / 'fsmo').write_text('PRIMARY')
            assert request('DELETE', '/api/computers/SECONDARY%24?remove_dead_dc=true')[0] == 200
            assert ['samba-tool', 'domain', 'demote', '--remove-other-dead-server=SECONDARY'] in calls()
            group = "R&D's #1 / Brasil"
            assert request('DELETE', '/api/groups/' + urllib.parse.quote(group, safe=''))[0] == 200
            assert ['samba-tool', 'group', 'delete', group] in calls()
            assert request('DELETE', '/api/groups/Domain%20Admins')[0] == 403
            ou = "OU=R&D's Lab,DC=example,DC=test"
            path = '/api/ou/' + urllib.parse.quote(ou, safe='')
            assert request('DELETE', path)[0] == 400
            assert request('DELETE', path + '?recursive=true')[0] == 200
            assert ['samba-tool', 'ou', 'delete', ou, '--force-subtree-delete'] in calls()
            assert request('DELETE', '/api/ou/OU%3DDomain%20Controllers%2CDC%3Dexample%2CDC%3Dtest?recursive=true')[0] == 403
            before = len(calls())
            assert request('DELETE', path + '?recursive=true&dry_run=true')[0] == 200
            assert all(call[0] in ['testparm', 'ldbsearch'] for call in calls()[before:]), 'Dry run executed a mutation'
            # Backend rejection occurs before filesystem or service changes.
            for role in ['DC', 'RODC']:
                before = len(calls())
                status, result = request('POST', '/api/provision/join-dc', {
                    'realm': 'EXAMPLE.TEST', 'target_dc_ip': '192.0.2.10',
                    'admin_username': 'Administrator', 'admin_password': 'test-only-password',
                    'domain_role': role, 'dns_backend': 'BIND9_DLZ', 'dry_run': False})
                assert status == 400, result
                assert len(calls()) == before
            before = len(calls())
            status, result = request('POST', '/api/provision/new-dc', {
                'realm': 'EXAMPLE.TEST', 'workgroup': 'EXAMPLE',
                'hostname_fqdn': 'primary.example.test', 'admin_password': 'test-only-password',
                'dns_backend': 'BIND9_DLZ', 'dry_run': False})
            assert status == 400, result
            assert len(calls()) == before
            assert request('GET', '/api/forensics', auth=False)[0] == 401
            assert request('GET', '/api/forensics')[1]['data']['reports'] == []
            assert request('POST', '/api/forensics/captures', {'baseline_id': '../invalid'})[0] == 400
            code, started = request('POST', '/api/forensics/captures', {'label': 'HTTP regression'})
            assert code == 202, started
            job_id = started['data']['id']
            for _ in range(100):
                _, state = request('GET', '/api/forensics/jobs/' + job_id)
                if state['data']['status'] != 'running': break
                time.sleep(.05)
            assert state['data']['status'] == 'completed', state
            report_id = state['data']['result']['report_id']
            assert request('GET', '/api/forensics/reports/' + report_id)[0] == 200
            req = urllib.request.Request(f'http://127.0.0.1:{port}/api/forensics/reports/{report_id}/html', headers={'Authorization': 'Bearer ' + token()})
            with urllib.request.urlopen(req, timeout=5) as html:
                assert 'text/html' in html.headers['Content-Type']
                assert 'sandbox' in html.headers['Content-Security-Policy']
                assert html.headers['Cache-Control'] == 'no-store'
                assert b'<!doctype html>' in html.read()
            print('PASS: computer/DC detection and deletion, local DC protection, DC metadata cleanup, '
                  'group/OU special characters, recursive OU opt-in, protected objects, dry-run and DLZ rejection')
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == '__main__':
    main()
