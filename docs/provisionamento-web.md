# Provisionamento, reingresso e reaplicação pela interface

O assistente executa os trabalhos no próprio servidor da console. Não é um executor
SSH genérico para qualquer máquina. Instale/abra a console no servidor que entrará no
AD e informe um DC gravável como parceiro. As rotas Nginx existentes são preservadas.

## Operações

- **Novo domínio**: salva a configuração anterior, instala dependências ausentes e
  provisiona SAMBA_INTERNAL com nível 2016. Uma base AD já existente bloqueia a
  criação de outro domínio por cima dela. Schema 2019 ou superior é verificado.
- **Ingresso**: valida DNS SRV diretamente no parceiro na porta 53, níveis funcionais
  e funções FSMO; instala/configura o servidor no papel DC, RODC ou membro.
- **Reingresso com backup automático**: para o secundário, salva uma cópia consistente
  da base local, verifica o arquivo/hash e despromove o DC anterior. Só então limpa
  os diretórios locais e ingressa no papel selecionado. Permite DC → RODC, RODC → DC,
  DC → membro, membro → DC e repetição do mesmo papel. A remoção de conta órfã após
  falha da despromoção exige marcar a opção específica na tela.
- **Reaplicar configuração**: preserva o ingresso/base, detecta o papel atual e
  reaplica DNS/BIND, firewall, NTP, catálogo global e TLS selecionados.

Qualquer função FSMO pertencente ao alvo bloqueia sua limpeza/despromoção. Primeiro
transfira as funções pela tela **Computadores & DCs**. Um nome novo já ocupado por
outra conta também bloqueia a troca antes de despromover o servidor atual.

## Backups e falhas

Os trabalhos criam `/var/backups/astral-ad-dns/provision/ID`, com manifesto sem senhas,
cópia de configuração e estado local, arquivo `previous-state.tar.gz` e SHA256. O
backend expõe histórico e download somente a administradores autenticados. A pasta
é 0700 e o arquivo é 0600; ele contém segredos do domínio. A base local é copiada com
os serviços Samba parados. Os dados de banco da Step-CA não fazem parte dessa cópia
de configuração; uma CA existente não é apagada ou recriada pelo reingresso.

Antes de alterações remotas, uma falha restaura configuração/base e estados dos
serviços capturados. Depois de despromoção/novo ingresso, não se pode simplesmente
religar uma base DC antiga: a associação já pode ter mudado no AD. Nesse caso o
backup é preservado, a tela mostra o estágio e oferece **Retomar pela interface**.
Uma falha de configuração depois de ingresso concluído oferece reaplicação, sem
obrigar outra despromoção. O histórico permite recuperar os parâmetros, solicitando
novamente as credenciais; senhas não são gravadas no navegador ou no manifesto.

A execução é assíncrona. A tela consulta `/api/provision/jobs/ID`, mostra andamento e
retoma a consulta após reabertura. Reinício do backend marca trabalhos anteriores
como interrompidos, exigindo conferir o histórico antes de uma nova execução.

## Comparação com fedoradc-SSL(3).py

| Etapa do script de referência | Integração web |
|---|---|
| Pacotes dnf | Detecção dnf/yum, apt, pacman e zypper; mapa por ferramenta e verificação após instalar |
| Hostname/hosts/interface | FQDN e IPv4 locais validados; demais entradas hosts preservadas; interface opcional |
| Limpeza inicial | Backup consistente e proteção FSMO antes da limpeza; sem apagar CA, logs ou dados de outros módulos |
| iptables | Insere regras ausentes, mantém políticas/regras existentes e instala persistência idempotente |
| firewalld | Se ativo, autoriza também as portas nas zonas ativas, sem remover sua configuração |
| NTP | Chrony/chronyd conforme a distribuição e socket assinado ntp_signd |
| Samba/BIND | SAMBA_INTERNAL :53; recursão BIND somente 127.0.0.1:5353, forwarders informados na tela |
| PKI/TLS | Step-CA opcional, CA existente preservada, bootstrap remoto por fingerprint, cadeia verificada e timer de renovação |
| Schema/níveis | Novo domínio em 2016, schema mínimo 2019; ingresso adapta o nível do DC ao domínio sem elevar a floresta existente |
| Partições DNS | Completa msDS-SDReferenceDomain ausente em DC gravável, após backup |
| DNS reverso | Zona /24, PTR, A e NS conforme o papel; aliases CA somente ao criar a autoridade local |
| Catálogo global | Configura o bit GC preservando os outros bits de options; verifica isGlobalCatalogReady e listeners 3268/3269 |
| SYSVOL | Sincronização SMB assinada no ingresso de DC/RODC e verificações de ACL |

No arquivo recebido, GC aparece nas portas e nos SANs do certificado. A ativação
explícita em NTDS Settings e a confirmação de prontidão foram acrescentadas no fluxo.
Em RODC, a alteração do bit GC é enviada ao DC gravável parceiro, usando o DN
NTDS do próprio RODC; não se força escrita local em uma partição somente leitura.

O firewall não executa `iptables -F`, não troca políticas para DROP/ACCEPT e não
substitui regras por permissões genéricas. Portas de bancos 1433/1521 do script não
são abertas como requisito do AD. BIND :5353 permanece restrito ao loopback. Serviços
UFW ativos recebem as permissões correspondentes também em sua política persistente.

## Distribuições e limites

Não se presume Fedora. Há adaptadores de pacotes para as famílias Fedora/RHEL,
Debian/Ubuntu, Arch e openSUSE, com nomes de units e trust stores detectados. O host
precisa disponibilizar Samba AD DC e systemd; versões/repos que não ofereçam esses
componentes ou nível 2016 retornam erro na tela antes da limpeza. Isso não equivale
a suporte testado em toda distribuição/versão Linux. Os testes de CI usam hosts e
comandos simulados; a validação de replicação, GC e certificados reais ocorre no host.

## Nginx e a porta da CA

A porta preferida de uma nova CA é configurável (8443). Antes de qualquer
limpeza, o configurador busca uma porta TCP/UDP livre: tenta a preferida, 9443,
10443 e outras portas disponíveis. Ele instala as regras correspondentes, usa a
porta escolhida na CA/URL/renovação e a informa no resultado da tela. No dc-erp, 8443 já é usada pelo Nginx
para o auth-service; o provisionamento não ocupa essa porta nem altera essas rotas.
Uma CA existente mantém sua URL/configuração. Certificados novos usam SANs do FQDN,
nome curto, domínio, LDAP e IPv4. A validade solicitada precisa ser aceita pela CA.
A chave Samba é armazenada sem senha, com modo 0600, para permitir início automático;
`--insecure` do Step nesse comando autoriza a chave sem senha, sem desligar a
validação TLS da CA, que usa URL HTTPS, raiz confiável e validação da cadeia.
