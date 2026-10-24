const assert = require('node:assert/strict');
const path = require('node:path');
const { JSDOM } = require('../web/node_modules/jsdom');
const dom = new JSDOM('<!doctype html><div id="root"></div>', { url: 'https://ad.example.test/ad/' });
Object.assign(global, { window: dom.window, document: dom.window.document, localStorage: dom.window.localStorage,
  EventTarget: dom.window.EventTarget, CustomEvent: dom.window.CustomEvent, IS_REACT_ACT_ENVIRONMENT: true });
window.confirm = () => { throw Error('Native dialogs are forbidden'); };
const calls = [];
const data = {
 '/api/auth/me': { success: true, data: { username: 'administrator', provider: 'AD', is_admin: true } },
 '/api/status': { realm: 'EXAMPLE.TEST', users_count: 1, groups_count: 1, computers_count: 2, zones_count: 1 },
 '/api/bind/status': { service_name: 'named', service_active: true, syntax_valid: true, listening_on_5353: true, loopback_only: true, forwarders: ['9.9.9.9'], warnings: [] },
 '/api/bind/logs': { success: true, data: [] },
 '/api/groups': { success: true, data: [{ name: "R&D's Group" }] },
 '/api/computers': { success: true, data: [{ name: 'PRIMARY$', is_dc: true, is_local: true, is_primary: true }, { name: 'SECONDARY$', is_dc: true, is_local: false, is_primary: false, is_rodc: false }, { name: 'READONLY$', is_dc: true, is_primary: false, is_local: false, is_rodc: true }] },
 '/api/forensics': { success: true, data: { snapshots: [{ id: 'snp_' + 'a'.repeat(32), label: 'Reference', status: 'complete' }], reports: [{ id: 'rep_' + 'b'.repeat(32), created_at: '2026-10-23', analyst: 'tester', status: 'partial' }] } },
 ['/api/forensics/reports/rep_' + 'b'.repeat(32)]: { success: true, data: { id: 'rep_' + 'b'.repeat(32), snapshot: { status: 'partial' } } },
 '/api/backups': { success: true, data: [{ filename: 'domain.tar.bz2', size_human: '1 MB' }] },
 '/api/provision/preflight': { fqdn: 'dc.example.test', samba_installed: true, ports_open: [] },
 '/api/provision/verify-ad-dns': { success: true, data: {} },
};
global.fetch = async (url, options = {}) => {
  const route = url.replace(/^\/ad/, '');
  calls.push([route, options]);
  if (route === '/api/provision/join-dc') return {ok:true,json:async()=>({success:true,data:{job_id:'c'.repeat(32)}})};
  if (route === '/api/provision/jobs/'+'c'.repeat(32)) return {ok:true,json:async()=>({success:true,data:{state:'finished',result:{success:true,message:'Provisionamento concluido',steps_completed:['Backup automatico verificado','Catalogo global confirmado'],backup_path:'/var/backups/astral-ad-dns/provision/test'}}})};
  return { ok: true, text: async () => '<!doctype html><html><body>Forensic test report</body></html>', json: async () => data[route] || { success: true, message: 'OK', data: [] } };
};
const bundle = path.resolve(__dirname, '../web/node_modules/.cache/ad-app.cjs');
require('../web/node_modules/esbuild').buildSync({ entryPoints: [path.resolve(__dirname, '../web/src/App.jsx')], outfile: bundle, bundle: true, platform: 'node', format: 'cjs', external: ['react'] });
const React = require('../web/node_modules/react');
const { createRoot } = require('../web/node_modules/react-dom/client');
const { act } = React;
const App = require(bundle).default;
const button = text => [...document.querySelectorAll('button')].find(node => node.textContent.trim() === text);
const click = async node => { assert(node, 'Expected button'); await act(async () => node.click()); };
(async () => {
  const root = createRoot(document.getElementById('root'));
  await act(async () => root.render(React.createElement(App)));
  await click(button('BIND 9 Recursivo'));
  assert(document.body.textContent.includes('Sintaxe: válida'));
  await click(button('Validar plano'));
  assert(calls.some(([route, options]) => route === '/api/bind/forwarders' && JSON.parse(options.body).dry_run));
  await click([...document.querySelectorAll('aside button')].find(node => node.textContent.includes('Computadores & DCs')));
  assert(document.body.textContent.includes('Primário protegido'));
  assert.equal([...document.querySelectorAll('button')].filter(node => node.textContent === 'Despromover').length, 2);
  await click(button('Promover a principal'));
  assert(document.querySelector('[aria-label="Promover secundário a principal"]'));
  assert(document.body.textContent.includes('O antigo principal permanece ativo como secundário'));
  await click(button('Cancelar'));
  await click(button('Tornar gravável'));
  assert(document.querySelector('[aria-label="Converter RODC em DC gravável secundário"]'));
  assert(button('Executar transição').disabled);
  assert(document.querySelector('[role="dialog"] input[type="checkbox"]'));
  await click(button('Cancelar'));
  await click(button('Despromover'));
  assert(document.querySelector('[aria-label="Despromover DC secundário"]'));
  await click(button('Cancelar'));
  await click(button('Forense AD'));
  assert(document.querySelector('[aria-label="Snapshot de referência"]'));
  await click(button('Ver HTML5'));
  const frame = document.querySelector('iframe[title="Relatório forense HTML5"]');
  assert(frame);
  assert.equal(frame.getAttribute('sandbox'), '');
  assert(frame.getAttribute('srcdoc').includes('Forensic test report'));
  assert(document.body.textContent.includes('Coleta parcial'));
  assert(button('Exportar HTML5'));
  await click(button('Backups'));
  assert(document.querySelector('input[type="file"]'));
  const selector = document.querySelector('[aria-label="Backup para recuperação"]');
  await act(async () => { selector.value = 'domain.tar.bz2'; selector.dispatchEvent(new window.Event('change', { bubbles: true })); });
  await click(button('Configurar recuperação'));
  assert(document.body.textContent.includes('Confirmo que os DCs do domínio original'));
  assert([...document.querySelectorAll('button')].find(node => node.textContent.includes('Simular Restauração')).disabled);
  await click(button('Assistente AD'));
  await click(button('Avançar'));
  await click(button('Avançar'));
  const partnerIp = document.querySelector('input[placeholder="Informe o IPv4 do DC existente"]');
  assert(partnerIp && partnerIp.value === '', 'AD partner must be entered, not hardcoded');
  const bindOption = [...document.querySelectorAll('label')].find(label => label.textContent.includes('BIND') && label.querySelector('input[type="checkbox"]'));
  assert(bindOption && !bindOption.querySelector('input').checked, 'local BIND must be optional');
  await click(button('Iniciar Provisionamento'));
  assert(!calls.some(([route]) => route === '/api/provision/join-dc'), 'must not join without the partner IP');
  assert(document.body.textContent.includes('Informe o IP do DC parceiro'));
  const tlsOption=[...document.querySelectorAll('label')].find(label=>label.textContent.includes('Configurar certificado LDAPS'));
  await click(tlsOption.querySelector('input'));
  assert.equal(document.querySelector('[aria-label="Porta da CA"]').value,'8443');
  assert(document.body.textContent.includes('escolhe outra livre e abre automaticamente'));
  await click(tlsOption.querySelector('input'));
  const {Simulate}=require('../web/node_modules/react-dom/test-utils');
  await act(async()=>{
    Simulate.change(partnerIp,{target:{value:'192.0.2.10'}});
    Simulate.change(document.querySelector('input[type="password"]'),{target:{value:'test-only-password'}});
  });
  await click(button('Iniciar Provisionamento'));
  assert(calls.some(([route])=>route==='/api/provision/jobs/'+'c'.repeat(32)));
  const posted=calls.find(([route])=>route==='/api/provision/join-dc');
  assert.deepEqual(JSON.parse(posted[1].body).upstream_forwarders,['8.8.8.8','1.1.1.1']);
  assert(document.body.textContent.includes('Catalogo global confirmado'));
  assert(document.body.textContent.includes('/var/backups/astral-ad-dns/provision/test'));
  assert.equal(localStorage.getItem('astral.provision.job'),null);

  await act(async () => root.unmount());
  console.log('PASS: BIND, DC protection/transitions, backup recovery, required partner IP, automatic CA port controls and asynchronous web provisioning');
  process.exit(0);
})().catch(error => { console.error(error); process.exit(1); });
