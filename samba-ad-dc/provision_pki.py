"""Preserve existing CA; optional web-managed Step-CA and signed Samba certificate."""
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from urllib.parse import urlsplit
from ad_operations import OperationError,atomic_write


def step_binary():
    return shutil.which('step-cli') or shutil.which('step')


def install_step(root,run):
    if step_binary() and shutil.which('step-ca'):return
    manager=next((m for m in ['dnf','yum','apt-get','pacman','zypper'] if shutil.which(m)),None)
    if manager in ['dnf','yum']:
        repo=root/'etc/yum.repos.d/smallstep.repo'
        if not repo.exists():
            atomic_write(repo,'[smallstep]\nname=Smallstep\nbaseurl=https://packages.smallstep.com/stable/fedora/\nenabled=1\nrepo_gpgcheck=0\ngpgcheck=1\ngpgkey=https://packages.smallstep.com/keys/smallstep-0x889B19391F774443.gpg\n',0o644)
        run([manager,'install','-y','step-cli','step-ca'])
    elif manager=='apt-get':
        key=root/'etc/apt/keyrings/smallstep.asc';key.parent.mkdir(parents=True,exist_ok=True)
        run(['curl','-fsSL','https://packages.smallstep.com/keys/apt/repo-signing-key.gpg','-o',str(key)])
        atomic_write(root/'etc/apt/sources.list.d/smallstep.sources','Types: deb\nURIs: https://packages.smallstep.com/stable/debian\nSuites: debs\nComponents: main\nSigned-By: /etc/apt/keyrings/smallstep.asc\n',0o644)
        run([manager,'update']);run(['env','DEBIAN_FRONTEND=noninteractive',manager,'install','-y','step-cli','step-ca'])
    elif manager=='pacman':run([manager,'-S','--needed','--noconfirm','step-cli','step-ca'])
    elif manager=='zypper':run([manager,'--non-interactive','install','step-cli','step-ca'])
    else:raise OperationError('Gerenciador nao suportado para instalar Step-CA automaticamente.')
    if not step_binary() or not shutil.which('step-ca'):raise OperationError('Os pacotes nao disponibilizaram step/step-ca.')


def configure_pki(request,root,run,samba_unit,steps):
    if not request.get('setup_step_ca'):return []
    initialize=bool(request.get('initialize_ca'))
    if initialize and request['kind']!='new':
        raise OperationError('Uma CA nova so pode ser inicializada em novo dominio; reingresso preserva a CA existente.')
    password=request.get('cert_password','')
    if not password:raise OperationError('Informe a senha da PKI na tela, sem reutilizar automaticamente a senha do AD.')
    install_step(root,run)
    cli = step_binary()
    home=root/'etc/step-ca';ca_config=home/'config/ca.json'
    tls=root/'etc/samba/tls';tls.mkdir(parents=True,exist_ok=True,mode=0o700)
    if initialize and ca_config.exists():
        initialize = False
        steps.append('CA local existente reutilizada; raiz, chaves e politica preservadas.')
    ca_port=int(request.get('ca_port',8443))
    configured_port=ca_port
    if ca_config.exists():
        address=json.loads(ca_config.read_text()).get('address','')
        if ':' in address: configured_port=int(address.rsplit(':',1)[1])
    url=request.get('ca_url') or 'https://'+request['host_ip']+':'+str(configured_port)
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OperationError('URL da CA deve ser HTTPS, sem credenciais/query.')
    request['ca_url'],request['ca_port']=url,configured_port
    provisioner=request.get('ca_provisioner') or 'admin@'+request['realm'].lower()
    with tempfile.TemporaryDirectory(prefix='astral-pki-',dir=tls) as temp:
        secret=Path(temp)/'password';atomic_write(secret,password)
        if initialize:
            if ca_config.exists():raise OperationError('Ja existe uma CA local; sua chave/identidade nao sera substituida.')
            listeners=run(['ss','-H','-lntup','( sport = :'+str(ca_port)+' )'])
            if listeners.strip(): raise OperationError('Porta da CA '+str(ca_port)+' ocupada. Escolha outra porta na tela; Nginx e outros servicos foram preservados.')
            try: exists=run(['getent','passwd','step']).strip()
            except OperationError: exists=''
            if not exists: run(['useradd','--system','--user-group','--home-dir','/etc/step-ca','--shell','/usr/sbin/nologin','step'])
            home.mkdir(parents=True,exist_ok=True,mode=0o700)
            permanent=home/'password.txt';atomic_write(permanent,password)
            run(['env','STEPPATH='+str(home),cli,'ca','init','--name',request['realm']+' Root CA',
                 '--dns',request['hostname_fqdn'],'--dns',request['host_ip'],'--dns','ca.'+request['realm'].lower(),
                 '--address',request['host_ip']+':'+str(ca_port),'--provisioner',provisioner,'--password-file',str(permanent),'--deployment-type','standalone'])
            data=json.loads(ca_config.read_text());claims=data.setdefault('authority',{}).setdefault('claims',{})
            claims.update(maxTLSCertDuration='8760h',defaultTLSCertDuration='8760h',disableRenewal=False)
            provisioners=data['authority'].setdefault('provisioners',[])
            for existing in provisioners:
                existing.setdefault('claims',{}).update(maxTLSCertDuration='8760h',defaultTLSCertDuration='8760h',disableRenewal=False)
            if not any(item.get('type')=='ACME' for item in provisioners):
                provisioners.append({'type':'ACME','name':'dc-auto-enroll'})
            atomic_write(ca_config,json.dumps(data,indent=2),0o600)
            run(['chown','-R','step:step',str(home)])
            unit='[Unit]\nDescription=Astral Step Certificate Authority\nAfter=network-online.target\n[Service]\nUser=step\nGroup=step\nEnvironment=STEPPATH=/etc/step-ca\nWorkingDirectory=/etc/step-ca\nExecStart='+shutil.which('step-ca')+' /etc/step-ca/config/ca.json --password-file /etc/step-ca/password.txt\nRestart=on-failure\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n'
            atomic_write(root/'etc/systemd/system/step-ca.service',unit,0o644)
            run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','step-ca'])
            ca_root=home/'certs/root_ca.crt'
        elif ca_config.exists() and parsed.hostname in [request['host_ip'],request['hostname_fqdn']]:
            run(['systemctl','start','step-ca'])
            ca_root=home/'certs/root_ca.crt'
        else:
            ca_root=tls/'trusted-step-root.crt'
            fingerprint=request.get('ca_fingerprint','').replace(':','').lower()
            if not re.fullmatch('[a-f0-9]{64}',fingerprint):raise OperationError('Informe o fingerprint SHA256 da CA existente para validar o bootstrap.')
            run(['env','STEPPATH='+temp,cli,'ca','bootstrap','--ca-url',url,'--fingerprint',fingerprint])
            shutil.copy2(Path(temp)/'certs/root_ca.crt',ca_root)
        for attempt in range(15):
            try:
                run([cli,'ca','health','--ca-url',url,'--root',str(ca_root)])
                break
            except OperationError:
                if attempt==14: raise
                time.sleep(1)
        cert,key=Path(temp)/'dc.crt',Path(temp)/'dc.key'
        sans=[request['hostname_fqdn'],request['netbios_name'].lower(),request['realm'].lower(),'ldap.'+request['realm'].lower(),request['host_ip']]
        # Match the working Arch script: ca certificate uses password-file.
        # no-password/insecure belong to other Step subcommands and are not
        # required here (the issued service key is unencrypted by default).
        sans += ['_ldap._tcp.dc._msdcs.'+request['realm'].lower(), '_kerberos._tcp.dc._msdcs.'+request['realm'].lower(), '_gc._tcp.'+request['realm'].lower(), 'ca.'+request['realm'].lower(), 'pki.'+request['realm'].lower(), '127.0.0.1']
        command=[cli,'ca','certificate',request['hostname_fqdn'],str(cert),str(key),
                 '--ca-url='+url,'--root='+str(ca_root),'--provisioner='+provisioner,
                 '--password-file='+str(secret),'--kty=RSA','--size=2048',
                 '--not-after='+str(int(request.get('ca_cert_hours',8760)))+'h']
        for san in sans:command+=['--san='+san]
        run(command)
        run(['openssl','verify','-CAfile',str(ca_root),'-untrusted',str(cert),str(cert)])
        atomic_write(tls/'dc.crt',cert.read_bytes(),0o644);atomic_write(tls/'dc.key',key.read_bytes(),0o600)
        atomic_write(tls/'ca.crt',ca_root.read_bytes(),0o644)
    if shutil.which('update-ca-trust'):
        anchor=root/'etc/pki/ca-trust/source/anchors/astral-step-root.crt';atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['update-ca-trust'])
    elif shutil.which('update-ca-certificates'):
        anchor=root/'usr/local/share/ca-certificates/astral-step-root.crt';atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['update-ca-certificates'])
    elif shutil.which('trust'):
        anchor=root/'etc/ca-certificates/trust-source/anchors/astral-step-root.crt'
        atomic_write(anchor,(tls/'ca.crt').read_bytes(),0o644)
        run(['trust','extract-compat'])
    else:raise OperationError('Ferramenta de trust store da distribuicao nao encontrada.')
    # Renewal uses the existing certificate/key and does not regenerate the CA.
    config={'step_binary':cli,'url':url,'cert':str(tls/'dc.crt'),'key':str(tls/'dc.key'),'root':str(tls/'ca.crt'),'unit':samba_unit,'renew_before_seconds':min(604800,max(1800,int(request.get('ca_cert_hours',8760))*1200))}
    atomic_write(root/'etc/astral-ad-dns/tls-renew.json',json.dumps(config))
    script="""#!/usr/bin/python3
import json,subprocess
from pathlib import Path
c=json.loads(Path('/etc/astral-ad-dns/tls-renew.json').read_text())
if subprocess.run(['openssl','x509','-in',c['cert'],'-checkend',str(c.get('renew_before_seconds',604800)),'-noout'],capture_output=True).returncode:
    subprocess.run([c.get('step_binary','step'),'ca','renew',c['cert'],c['key'],'--ca-url',c['url'],'--root',c['root'],'--force'],check=True)
    subprocess.run(['systemctl','restart',c['unit']],check=True)
"""
    atomic_write(root/'usr/local/lib/astral-ad-dns/tls-renew.py',script,0o700)
    atomic_write(root/'etc/systemd/system/astral-ad-tls-renew.service','[Unit]\nDescription=Astral Samba TLS renewal\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/lib/astral-ad-dns/tls-renew.py\n',0o644)
    atomic_write(root/'etc/systemd/system/astral-ad-tls-renew.timer','[Unit]\nDescription=Astral Samba TLS renewal timer\n[Timer]\nOnCalendar=*-*-* *:00/15:00\nPersistent=true\nRandomizedDelaySec=120\n[Install]\nWantedBy=timers.target\n',0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','astral-ad-tls-renew.timer'])
    steps.append('Certificado LDAPS assinado, cadeia validada, trust store e renovacao automatica configurados; CA anterior preservada.')
    return [('tls enabled','yes'),('tls keyfile',str(tls/'dc.key')),('tls certfile',str(tls/'dc.crt')),('tls cafile',str(tls/'ca.crt'))]
