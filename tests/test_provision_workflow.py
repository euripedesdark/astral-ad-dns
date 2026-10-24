import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'samba-ad-dc'
sys.path.insert(0,str(SCRIPTS))
import provision_workflow as flow
import provision_system as system
from ad_operations import OperationError


class Host:
    def __init__(self,root,fail=None,fsmo_target=False):
        self.root,self.fail,self.fsmo_target=root,fail,fsmo_target
        self.calls=[]; self.rules=[]
    def __call__(self,args):
        self.calls.append(args)
        if self.fail and self.fail(args): raise OperationError('injected failure')
        if args[0]=='systemctl':
            if args[1]=='is-active': return 'active' if args[2] in ['samba','named','chronyd','smb','winbind'] else 'inactive'
            if args[1]=='is-enabled': return 'enabled'
            if args[1]=='show': return 'loaded' if args[2] in ['samba','named','chronyd','smb','winbind'] else 'not-found'
        if args[0]=='hostname': return '192.0.2.20'
        if args[0]=='dig': return 'domain.test. 900 IN SRV 0 100 389 primary.example.test.'
        if args[0]=='testparm':
            if '--parameter-name=netbios name' in args:return 'SECONDARY'
            if '--parameter-name=realm' in args:return 'EXAMPLE.TEST'
            if '--parameter-name=ad dc functional level' in args:return '2016' if any(a.startswith('--option') for a in args) else '2008_R2'
        if args[:3]==['samba-tool','domain','info']:return 'DC netbios name : PRIMARY'
        if args[:3]==['samba-tool','fsmo','show']:
            return '\n'.join(label+' owner: CN=NTDS Settings,CN='+('SECONDARY' if self.fsmo_target else 'PRIMARY')+',CN=Servers' for label in flow.FSMO)
        if args[:3]==['samba-tool','computer','show']:
            return 'userAccountControl: 8192\nprimaryGroupID: 516\n'
        if args[:4]==['samba-tool','domain','level','show']:
            return 'Domain function level: (Windows) 2016\nForest function level: (Windows) 2016'
        if args[:3]==['samba-tool','domain','demote']:
            archives=list((self.root/'var/backups/astral-ad-dns/provision').glob('*/previous-state.tar.gz'))
            assert archives, 'demotion must never run without an archive'
            with tarfile.open(archives[-1]) as archive: assert archive.getmembers()
        if args[:3] in [['samba-tool','domain','join'],['samba-tool','domain','provision']]:
            config=self.root/'etc/samba/smb.conf';config.parent.mkdir(parents=True,exist_ok=True)
            config.write_text('[global]\n realm = EXAMPLE.TEST\n')
            db=self.root/'var/lib/samba/private/sam.ldb';db.parent.mkdir(parents=True,exist_ok=True);db.write_text('new database')
        if args[:3]==['samba-tool','drs','showrepl']:return json.dumps({'repsFrom':[{'consecutive failures':0,'last success':123}]})
        if args[0]=='getent':return 'chrony:x:1:'
        if args[0]=='iptables-save':return '*filter\n:INPUT DROP [0:0]\nCOMMIT\n'
        if args[0]=='iptables':
            if args[1]=='-C' and args[3:] not in self.rules:raise OperationError('missing rule')
            if args[1]=='-I':self.rules.append(args[4:])
        if args[0]=='/usr/bin/python3':return json.dumps({'ready':True,'global_catalog_enabled':True})
        return ''


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.config=self.root/'etc/samba/smb.conf';self.config.parent.mkdir(parents=True)
        self.config.write_text('[global]\n realm = EXAMPLE.TEST\n netbios name = SECONDARY\n')
        self.db=self.root/'var/lib/samba/private/sam.ldb';self.db.parent.mkdir(parents=True);self.db.write_text('old database')
        (self.db.parent/'stale.tdb').write_text('stale')
        self.request={'realm':'EXAMPLE.TEST','target_dc_ip':'192.0.2.10','netbios_name':'SECONDARY','domain_role':'RODC',
                      'admin_username':'Administrator','admin_password':'secret-test-only','upstream_forwarders':['9.9.9.9'], 'rejoin':True,'setup_bind_hybrid':True}
        self.available=patch.object(system.shutil,'which',side_effect=lambda name:'/usr/bin/'+name)
        self.available.start();self.addCleanup(self.available.stop)
    def execute(self,request=None,host=None,bind=None):
        return flow.execute(request or self.request,self.root,host or Host(self.root),bind or (lambda *_:['BIND ready']))
    def test_dc_to_rodc_backs_up_before_demotion_cleans_old_state_and_joins(self):
        host=Host(self.root);result=self.execute(host=host)
        self.assertTrue(result['success'],result)
        self.assertEqual(self.db.read_text(),'new database')
        self.assertFalse((self.db.parent/'stale.tdb').exists())
        self.assertEqual((Path(result['backup_path'])/'files/var/lib/samba/private/sam.ldb').read_text(),'old database')
        join=next(args for args in host.calls if args[:3]==['samba-tool','domain','join'])
        self.assertIn('RODC',join);self.assertIn('--option=ad dc functional level = 2016',join)
        self.assertNotIn('--netbios-name',join)
        self.assertIn('127.0.0.1:5353',self.config.read_text())
        manifest=(Path(result['backup_path'])/'manifest.json').read_text()
        self.assertNotIn(self.request['admin_password'],manifest)
    def test_primary_or_any_fsmo_owner_is_not_cleaned(self):
        host=Host(self.root,fsmo_target=True);result=self.execute(host=host)
        self.assertFalse(result['success']);self.assertIn('FSMO',result['message'])
        self.assertEqual(self.db.read_text(),'old database')
        self.assertFalse(any(args[:2]==['systemctl','stop'] for args in host.calls))
    def test_backup_failure_never_demotes_or_cleans(self):
        host=Host(self.root)
        with patch.object(flow.tarfile,'open',side_effect=OSError('disk full')):result=self.execute(host=host)
        self.assertFalse(result['success']);self.assertEqual(self.db.read_text(),'old database')
        self.assertFalse(any(args[:3]==['samba-tool','domain','demote'] for args in host.calls))
        self.assertIn(['systemctl','start','samba'],host.calls)
    def test_demotion_failure_requires_explicit_orphan_cleanup(self):
        host=Host(self.root,fail=lambda args:args[:3]==['samba-tool','domain','demote'])
        result=self.execute(host=host)
        self.assertFalse(result['success']);self.assertTrue(result['recovery_required'])
        self.assertEqual(self.db.read_text(),'old database')
        self.assertNotIn(['systemctl','start','samba'],host.calls)
    def test_explicit_orphan_cleanup_can_recover_failed_demotion(self):
        host=Host(self.root,fail=lambda args:args[:3]==['samba-tool','domain','demote'] and not any(a.startswith('--remove-other') for a in args))
        result=self.execute(dict(self.request,clean_existing=True),host)
        self.assertTrue(result['success'],result)
        self.assertTrue(any('--remove-other-dead-server=SECONDARY' in args for args in host.calls))
    def test_join_failure_after_demotion_preserves_backup_without_starting_old_dc(self):
        host=Host(self.root,fail=lambda args:args[:3]==['samba-tool','domain','join'])
        result=self.execute(host=host)
        self.assertFalse(result['success']);self.assertTrue(result['recovery_required'])
        self.assertTrue((Path(result['backup_path'])/'previous-state.tar.gz').exists())
        self.assertNotIn(['systemctl','start','samba'],host.calls)
    def test_configure_only_never_demotes_or_rejoins(self):
        host=Host(self.root)
        result=self.execute(dict(self.request,kind='configure'),host)
        self.assertTrue(result['success'],result);self.assertEqual(self.db.read_text(),'old database')
        self.assertFalse(any(args[:3] in [['samba-tool','domain','join'],['samba-tool','domain','demote']] for args in host.calls))
    def test_bind_failure_is_pending_configuration_and_can_reapply(self):
        def fail(*_):raise OperationError('named listener failed')
        result=self.execute(bind=fail)
        self.assertFalse(result['success']);self.assertTrue(result['joined']);self.assertTrue(result['configuration_pending'])
        self.assertIn('192.0.2.10',self.config.read_text());self.assertNotIn('127.0.0.1:5353',self.config.read_text())
        retry=self.execute(dict(self.request,kind='configure'))
        self.assertTrue(retry['success'],retry)
    def test_failed_preflight_preserves_live_ca_database(self):
        database=self.root/'etc/step-ca/db/data';database.parent.mkdir(parents=True);database.write_text('CA live database')
        result=self.execute(host=Host(self.root,fsmo_target=True))
        self.assertFalse(result['success']);self.assertEqual(database.read_text(),'CA live database')

    def test_port_selection_firewall_and_pki_url_use_same_available_port(self):
        flow.remove(self.root/'var/lib/samba');self.config.unlink()
        host=Host(self.root)
        def run(args):
            if args==['ss','-H','-lntup']:
                return 'tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("nginx"))'
            return host(args)
        def issue(request,root,run,samba,steps):
            request['ca_url']='https://'+request['host_ip']+':'+str(request['ca_port'])
            return []
        request=dict(self.request,kind='new',workgroup='EXAMPLE',domain_role='DC',netbios_name='PRIMARY',setup_step_ca=True,initialize_ca=True,cert_password='pki-secret',ca_port=8443)
        with patch.object(flow,'configure_pki',side_effect=issue): result=self.execute(request,run)
        self.assertTrue(result['success'],result)
        self.assertEqual(result['ca_port'],9443)
        self.assertTrue(result['ca_url'].endswith(':9443'))
        for protocol in ['tcp','udp']:
            self.assertIn(['-p',protocol,'--dport','9443','-j','ACCEPT'],host.rules)
        self.assertNotIn(['-p','tcp','--dport','8443','-j','ACCEPT'],host.rules)

    def test_tailscale_jump_remains_first_when_required_ports_are_inserted(self):
        host=Host(self.root)
        def run(args):
            if args==['iptables','-S','INPUT']: return '-P INPUT ACCEPT\n-A INPUT -j ts-input\n'
            return host(args)
        result=self.execute(host=run);self.assertTrue(result['success'],result)
        self.assertTrue(all(args[3]=='2' for args in host.calls if args[:2]==['iptables','-I']))

    def test_string_false_cannot_authorize_destructive_rejoin(self):
        result=self.execute(dict(self.request,rejoin='false'))
        self.assertFalse(result['success']);self.assertIn('booleano',result['message'])
        self.assertEqual(self.db.read_text(),'old database')

    def test_simulation_never_runs_packages_or_mutations(self):
        host=Host(self.root);result=self.execute(dict(self.request,dry_run=True),host)
        self.assertTrue(result['success']);self.assertEqual(host.calls,[])
        self.assertFalse((self.root/'var/backups').exists())
    def test_first_primary_install_is_a_web_workflow(self):
        flow.remove(self.root/'var/lib/samba');self.config.unlink()
        result=self.execute(dict(self.request,kind='new',workgroup='EXAMPLE',hostname_fqdn='primary.example.test',netbios_name='PRIMARY',domain_role='DC'))
        self.assertTrue(result['success'],result)
    def test_member_join_does_not_pass_dns_backend_or_enable_gc(self):
        host=Host(self.root);result=self.execute(dict(self.request,domain_role='MEMBER'),host)
        self.assertTrue(result['success'],result)
        join=next(args for args in host.calls if args[:3]==['samba-tool','domain','join'])
        self.assertFalse(any(arg.startswith('--dns-backend') for arg in join))
        self.assertFalse(any(args[0]=='/usr/bin/python3' for args in host.calls))
    def test_firewall_rules_are_added_idempotently_without_flush_or_policy_change(self):
        host=Host(self.root);result=self.execute(host=host);self.assertTrue(result['success'],result)
        count=len(host.rules)
        retry=self.execute(dict(self.request,kind='configure'),host);self.assertTrue(retry['success'],retry)
        self.assertEqual(len(host.rules),count)
        self.assertFalse(any(args[0]=='iptables' and ('-F' in args or '-P' in args) for args in host.calls))
        self.assertIn(['-p','tcp','--dport','3268','-j','ACCEPT'],host.rules)
        self.assertIn(['-p','tcp','--dport','3269','-j','ACCEPT'],host.rules)
    def test_missing_rejoin_opt_in_never_removes_existing_database(self):
        result=self.execute(dict(self.request,rejoin=False))
        self.assertFalse(result['success']);self.assertEqual(self.db.read_text(),'old database')

if __name__=='__main__':unittest.main()
