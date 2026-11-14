"""Independent Step-CA management: never joins, demotes, cleans or edits AD databases."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
from ad_operations import OperationError, checked_run, atomic_write
from provision_pki import install_step, step_binary

ROOT=Path('/')
TRUST=Path('/etc/astral-ad-dns/tls/root-ca.crt')

def fingerprint_of(cert_path, run=checked_run):
    output=run(['openssl','x509','-in',str(cert_path),'-noout','-fingerprint','-sha256'])
    return output.rsplit('=',1)[-1].replace(':','').strip().lower()

def inputs(request):
    url=str(request.get('ca_url') or '').strip()
    p=urlsplit(url)
    sha=str(request.get('ca_fingerprint') or '').replace(':','').strip().lower()
    if (p.scheme!='https' or not p.hostname or p.username or p.password or
        p.query or p.fragment or (p.path not in ('','/')) or
        not re.fullmatch(r'[0-9a-f]{64}',sha)):
        raise OperationError('Informe URL HTTPS da CA (sem caminho) e fingerprint SHA256 confiavel.')
    if p.hostname.lower() in ('localhost','127.0.0.1','::1'):
        raise OperationError('Use o endpoint da CA acessivel pela rede, nao localhost.')
    return url,sha

def bootstrap(request, run=checked_run):
    url,sha=inputs(request)
    install_step(ROOT,run,require_server=False)
    cli=step_binary()
    if not cli:raise OperationError('Step CLI nao instalado.')
    with tempfile.TemporaryDirectory(prefix='astral-ca-verify-') as home:
        run(['env','STEPPATH='+home,cli,'ca','bootstrap','--ca-url',url,'--fingerprint',sha])
        ca=Path(home)/'certs/root_ca.crt'
        if not ca.is_file() or fingerprint_of(ca,run)!=sha:
            raise OperationError('Fingerprint da raiz da CA nao corresponde ao valor confiavel informado.')
        run([cli,'ca','health','--ca-url',url,'--root',str(ca)])
        return ca.read_bytes()

def status():
    path=Path('/etc/step-ca/config/ca.json')
    local=None
    if path.is_file():
        data=json.loads(path.read_text())
        local={'address':data.get('address'),'dns_names':data.get('dnsNames',[]),
               'provisioners':[{'name':p.get('name'),'type':p.get('type')} for p in data.get('authority',{}).get('provisioners',[])]}
    cert=Path('/etc/samba/tls/dc.crt')
    return {'local_ca':local,'step_cli_installed':bool(step_binary()),
            'trusted_root_installed':TRUST.is_file(),
            'ldaps_certificate_installed':cert.is_file(),
            'ldaps_expiry': checked_run(['openssl','x509','-in',str(cert),'-noout','-enddate']).strip() if cert.is_file() else None}

def execute(request):
    action=request.get('action','status')
    if action=='status':return {'success':True,'details':status(),'steps_completed':[]}
    if action not in ('verify','trust'):
        raise OperationError('Operacao PKI nao suportada. Use verificar ou instalar CA raiz.')
    cert=bootstrap(request)
    steps=['Step CLI instalado/verificado na maquina local.',
           'Certificado publico da CA raiz obtido e validado pelo fingerprint SHA256.',
           'Conexao HTTPS e saude da Step-CA confirmadas.']
    if action=='trust':
        atomic_write(TRUST,cert,0o644)
        if shutil.which('update-ca-trust'):
            atomic_write(Path('/etc/pki/ca-trust/source/anchors/astral-step-root.crt'),cert,0o644)
            checked_run(['update-ca-trust'])
        elif shutil.which('update-ca-certificates'):
            atomic_write(Path('/usr/local/share/ca-certificates/astral-step-root.crt'),cert,0o644)
            checked_run(['update-ca-certificates'])
        elif shutil.which('trust'):
            atomic_write(Path('/etc/ca-certificates/trust-source/anchors/astral-step-root.crt'),cert,0o644)
            checked_run(['trust','extract-compat'])
        else:raise OperationError('Sistema nao possui ferramenta de atualizacao do trust store.')
        steps.append('CA raiz instalada no trust store do sistema, sem alterar Samba ou o dominio.')
    return {'success':True,'steps_completed':steps,'details':status()}
