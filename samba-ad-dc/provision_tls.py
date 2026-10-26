"""Existing host TLS material, independent from Step-CA enrollment."""
from pathlib import Path
from ad_operations import OperationError, atomic_write


def prepare_existing_tls(request, root, run, steps):
    mode = request.get('tls_mode', 'auto')
    if mode not in ['auto', 'existing', 'step-ca']:
        raise OperationError('Modo TLS invalido.')
    if mode == 'step-ca' or request.get('setup_step_ca'):
        if mode == 'existing':
            raise OperationError('Escolha certificados existentes ou emissao Step-CA.')
        return
    supplied = [request.get('tls_cert_path'), request.get('tls_key_path'), request.get('tls_ca_path')]
    if mode == 'existing' and not all(supplied):
        raise OperationError('Informe caminhos no servidor para certificado deste DC, chave privada e cadeia CA antes do ingresso.')
    if not any(supplied):
        # Only discover complete, conventional Samba sets. Never reuse a
        # partner DC private key or scan arbitrary filesystem directories.
        for directory, names in [('etc/samba/tls', ('dc.crt','dc.key','ca.crt')),
                                 ('var/lib/samba/private/tls', ('cert.pem','key.pem','ca.pem'))]:
            paths = [root/directory/name for name in names]
            if all(path.is_file() for path in paths):
                supplied = [str(path) for path in paths]
                break
        else:
            steps.append('TLS: nenhum conjunto existente encontrado; ingresso nativo nao exige Step-CA. Para LDAPS com CA confiavel, indique os certificados na interface.')
            return
    if not all(supplied):
        raise OperationError('Conjunto TLS incompleto; informe certificado, chave e cadeia CA na interface.')
    paths = [Path(value) for value in supplied]
    if not all(path.is_absolute() and path.is_file() for path in paths):
        raise OperationError('Arquivos TLS devem existir em caminhos absolutos no servidor.')
    cert, key, ca = map(str, paths)
    fqdn = request.get('hostname_fqdn') or request['netbios_name'].lower()+'.'+request['realm'].lower()
    try:
        run(['openssl','x509','-in',cert,'-noout','-checkend','0'])
        run(['openssl','verify','-purpose','sslserver','-verify_hostname',fqdn,'-CAfile',ca,cert])
        public_cert = run(['openssl','x509','-in',cert,'-pubkey','-noout']).strip()
        public_key = run(['openssl','pkey','-in',key,'-passin','pass:','-pubout']).strip()
        if not public_cert or public_cert != public_key:
            raise OperationError('Chave privada nao corresponde ao certificado.')
    except OperationError as error:
        raise OperationError('TLS existente invalido antes da limpeza. Indique certificado deste servidor, chave correspondente e cadeia CA completa: '+str(error)) from error
    request['_existing_tls'] = [path.read_bytes() for path in paths]
    steps.append('TLS existente validado antes da limpeza: nome, validade, cadeia e chave; nenhuma CA criada.')


def install_existing_tls(request, root):
    material = request.get('_existing_tls')
    if not material:
        return []
    directory = root/'etc/samba/tls'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, data, mode in zip(['dc.crt','dc.key','ca.crt'], material, [0o644,0o600,0o644]):
        atomic_write(directory/name,data,mode)
    return [('tls enabled','yes'), ('tls certfile',str(directory/'dc.crt')),
            ('tls keyfile',str(directory/'dc.key')), ('tls cafile',str(directory/'ca.crt'))]
