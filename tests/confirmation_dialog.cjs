// Run: npm ci --prefix web && node tests/confirmation_dialog.cjs
const path = require('node:path');
const bundle = path.resolve(__dirname, '../web/node_modules/.cache/ad-confirmation.cjs');
require('../web/node_modules/esbuild').buildSync({
  entryPoints: [path.resolve(__dirname, '../web/src/components/ConfirmationDialog.jsx')],
  outfile: bundle, bundle: true, platform: 'node', format: 'cjs', external: ['react'],
});
const assert = require('node:assert/strict');
const { JSDOM } = require('../web/node_modules/jsdom');
const dom = new JSDOM('<!doctype html><button id="trigger">Delete</button><div id="root"></div>', { url: 'https://ad.example.test/ad/' });
Object.assign(global, { window: dom.window, document: dom.window.document, EventTarget: dom.window.EventTarget, CustomEvent: dom.window.CustomEvent, IS_REACT_ACT_ENVIRONMENT: true });
window.confirm = () => { throw new Error('Native dialog must never be used'); };
const React = require('../web/node_modules/react');
const { createRoot } = require('../web/node_modules/react-dom/client');
const { act } = React;
const { default: ConfirmationDialog, confirmAction } = require(bundle);
(async () => {
  const root = createRoot(document.getElementById('root'));
  await act(async () => root.render(React.createElement(ConfirmationDialog)));
  const trigger = document.getElementById('trigger');
  trigger.focus();
  let decision;
  await act(async () => { decision = confirmAction("Excluir R&D's Lab?"); });
  assert(document.querySelector('[role="alertdialog"]').textContent.includes("R&D's Lab"));
  assert.equal(document.activeElement.textContent, 'Cancelar');
  await act(async () => document.querySelectorAll('[role="alertdialog"] button')[1].click());
  assert.equal(await decision, true);
  assert.equal(document.activeElement, trigger);
  await act(async () => { decision = confirmAction('Cancel test'); });
  await act(async () => document.querySelector('[role="alertdialog"] button').click());
  assert.equal(await decision, false);
  assert.equal(document.querySelector('[role="alertdialog"]'), null);
  await act(async () => { decision = confirmAction('Escape test'); });
  await act(async () => document.activeElement.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
  assert.equal(await decision, false);
  await act(async () => root.unmount());
  console.log('PASS: application confirmations accept, cancel, Escape, focus and no native dialogs');
})().catch(error => { console.error(error); process.exitCode = 1; });
