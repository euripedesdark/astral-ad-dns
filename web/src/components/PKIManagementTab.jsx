import React, {useEffect, useState} from 'react';

export default function PKIManagementTab({customFetch, showToast}) {
  const [url,setUrl]=useState('');
  const [fingerprint,setFingerprint]=useState('');
  const [busy,setBusy]=useState(false);
  const [status,setStatus]=useState(null);
  const [steps,setSteps]=useState([]);
  const [error,setError]=useState('');

  const call=async (action) => {
    setBusy(true);setError('');setSteps([]);
    try {
      const response=await customFetch('/api/provision/step-ca', action==='status' ? {} : {
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action,ca_url:url.trim(),ca_fingerprint:fingerprint.trim()})
      });
      const payload=await response.json();
      if (!response.ok || !payload.success) throw new Error(payload.message || 'Falha na operacao PKI');
      const result=payload.data || {};
      setStatus(result.details || result);
      setSteps(result.steps_completed || []);
      if(action!=='status') showToast?.('Operacao PKI concluida','success');
    } catch(e) {setError(e.message);}
    finally {setBusy(false);}
  };
  useEffect(()=>{call('status');},[]);
  const valid=/^https:\/\/[^\s/?#]+\/?$/.test(url.trim()) &&
    /^[a-f0-9:]{64,95}$/i.test(fingerprint.trim()) &&
    fingerprint.replace(/:/g,'').length===64;
  return <section className="space-y-5 max-w-3xl" aria-label="Gerenciamento de PKI">
    <header>
      <h2 className="text-xl font-bold text-slate-100">PKI / Certificados</h2>
      <p className="text-slate-400 text-sm mt-1">Gerencie a confianca da Step-CA em qualquer servidor Astral, sem ingressar ou despromover controladores AD.</p>
    </header>
    <div className="rounded-xl border border-slate-700 p-4 space-y-3 bg-slate-900">
      <h3 className="font-semibold">Estado local</h3>
      <p className="text-xs text-slate-400">Cliente Step: {status?.step_cli_installed ? 'instalado' : 'ausente'} · Raiz confiavel: {status?.trusted_root_installed ? 'instalada' : 'ausente'} · Certificado LDAPS: {status?.ldaps_certificate_installed ? 'encontrado' : 'ausente'}</p>
      {status?.ldaps_expiry && <p className="text-xs text-slate-400">Validade LDAPS: {status.ldaps_expiry}</p>}
      {status?.local_ca && <p className="text-xs text-cyan-300">Step-CA local: {status.local_ca.address || 'configurada'}</p>}
      <button type="button" disabled={busy} onClick={()=>call('status')} className="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded px-3 py-2 text-sm">Atualizar estado</button>
    </div>
    <div className="rounded-xl border border-slate-700 p-4 space-y-3 bg-slate-900">
      <h3 className="font-semibold">Confiar em uma Step-CA existente</h3>
      <p className="text-sm text-slate-400">O servidor verifica o fingerprint SHA256 antes de confiar na raiz. A verificacao nao altera certificados do Samba, usuarios, FSMO ou base do dominio.</p>
      <label className="block text-sm">URL HTTPS da CA
        <input aria-label="URL HTTPS da Step-CA" value={url} onChange={e=>setUrl(e.target.value)} autoComplete="off" placeholder="https://endereco-da-ca:porta" className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2" />
      </label>
      <label className="block text-sm">Fingerprint SHA256 confiavel da CA raiz
        <input aria-label="Fingerprint SHA256 da CA raiz" value={fingerprint} onChange={e=>setFingerprint(e.target.value)} autoComplete="off" placeholder="64 caracteres hexadecimais" className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs" />
      </label>
      <div className="flex flex-wrap gap-2">
        <button type="button" disabled={busy || !valid} onClick={()=>call('verify')} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded px-3 py-2 text-sm">Validar CA e HTTPS</button>
        <button type="button" disabled={busy || !valid} onClick={()=>call('trust')} className="bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 rounded px-3 py-2 text-sm">Instalar raiz confiavel</button>
      </div>
    </div>
    {busy && <p role="status" className="text-cyan-300">Executando operacao PKI no servidor...</p>}
    {error && <p role="alert" className="text-rose-300 border border-rose-700 p-3 rounded">{error}</p>}
    {steps.length>0 && <ol className="text-sm text-emerald-300 space-y-1 list-decimal pl-5">{steps.map((step,index)=><li key={index}>{step}</li>)}</ol>}
    <p className="text-xs text-slate-400">Para emitir ou renovar certificados, utilize a funcionalidade de certificados do controlador. Esta tela nao pede nem armazena senhas da CA.</p>
  </section>;
}
