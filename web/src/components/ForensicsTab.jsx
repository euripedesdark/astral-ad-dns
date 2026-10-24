import React, { useEffect, useState } from 'react';
import { FileText, RefreshCw, Download, Shield, AlertTriangle } from 'lucide-react';

export default function ForensicsTab({ customFetch, showToast }) {
  const [history, setHistory] = useState({ snapshots: [], reports: [] });
  const [baseline, setBaseline] = useState('');
  const [label, setLabel] = useState('');
  const [job, setJob] = useState(null);
  const [starting, setStarting] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);
  const [report, setReport] = useState(null);
  const [reportHtml, setReportHtml] = useState('');
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  const refresh = async () => {
    const response = await customFetch('/api/forensics');
    const result = await response.json();
    if (!response.ok || !result.success) throw new Error(result.message || 'Falha ao listar evidências');
    setHistory(result.data);
  };
  useEffect(() => { refresh().catch(error => setError(error.message)); }, []);
  const openReport = async id => {
    setLoadingReport(true); setError('');
    try {
      const response = await customFetch(`/api/forensics/reports/${encodeURIComponent(id)}`);
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.message || 'Falha ao verificar relatório');
      const document = await customFetch(`/api/forensics/reports/${encodeURIComponent(id)}/html`);
      if (!document.ok) {
        const failure = await document.json();
        throw new Error(failure.message || 'Falha ao abrir HTML5');
      }
      const html = await document.text();
      setReport(result.data); setReportHtml(html);
    } catch (failure) { setError(failure.message); setReport(null); setReportHtml(''); }
    finally { setLoadingReport(false); }
  };
  useEffect(() => {
    if (!job?.id || job.status !== 'running') return;
    let stopped = false;
    let timer;
    const poll = async () => {
      try {
        const response = await customFetch(`/api/forensics/jobs/${encodeURIComponent(job.id)}`);
        const result = await response.json();
        if (!response.ok || !result.success) throw new Error(result.message || 'Falha ao consultar captura');
        if (stopped) return;
        setJob(result.data);
        if (result.data.status === 'completed') {
          await refresh();
          if (result.data.result?.report_id) await openReport(result.data.result.report_id);
          showToast(result.data.result?.status === 'partial' ? 'Relatório pronto com coleta parcial; consulte as limitações.' : 'Relatório forense concluído.');
        } else if (result.data.status === 'failed') {
          setError(result.data.error || 'Falha na coleta');
        } else { timer = setTimeout(poll, 2000); }
      } catch (failure) {
        if (!stopped) { setError(failure.message); setJob(previous => ({ ...previous, status: 'unknown' })); }
      }
    };
    timer = setTimeout(poll, 1000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [job?.id, job?.status]);

  const capture = async event => {
    event.preventDefault(); setStarting(true); setError('');
    try {
      const response = await customFetch('/api/forensics/captures', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseline_id: baseline || undefined, label }) });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.message || 'Falha ao iniciar captura');
      setJob(result.data);
    } catch (failure) { setError(failure.message); }
    finally { setStarting(false); }
  };
  const exportFile = format => {
    const content = format === 'html' ? reportHtml : JSON.stringify(report, null, 2);
    const blob = new Blob([content], { type: format === 'html' ? 'text/html;charset=utf-8' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = window.document.createElement('a');
    anchor.href = url; anchor.download = `${report.id}.${format}`; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const busy = starting || job?.status === 'running';
  const rows = (history.reports || []).filter(item => JSON.stringify(item).toLowerCase().includes(filter.toLowerCase()));
  return <div className="space-y-5">
    <header className="bg-slate-900 border border-slate-700 rounded-xl p-5 space-y-2">
      <h2 className="flex items-center gap-2 text-lg font-bold text-cyan-300"><Shield className="w-5 h-5" />Forense Active Directory</h2>
      <p className="text-xs text-slate-300">Capture evidências, compare objetos por GUID e examine alterações de contas, grupos, ACLs, DNS, GPOs e SYSVOL.</p>
      <p className="text-xs text-slate-400">As consultas preservam a configuração do AD. Cada relatório mostra escopo, etapas indisponíveis, integridade SHA-256 e limites da análise.</p>
    </header>
    {error && <div role="alert" className="bg-rose-950/50 border border-rose-800 text-rose-200 p-4 rounded-xl text-xs whitespace-pre-wrap">{error}</div>}
    <form onSubmit={capture} className="bg-slate-900 border border-slate-700 rounded-xl p-5 grid gap-4 md:grid-cols-2 text-xs">
      <label>Nome / contexto da coleta<input aria-label="Contexto da coleta" value={label} maxLength={240} disabled={busy} onChange={event => setLabel(event.target.value)} placeholder="Ex.: referência antes da manutenção" className="block w-full mt-2 p-2 rounded bg-slate-950 border border-slate-700" /></label>
      <label>Snapshot de referência<select aria-label="Snapshot de referência" value={baseline} disabled={busy} onChange={event => setBaseline(event.target.value)} className="block w-full mt-2 p-2 rounded bg-slate-950 border border-slate-700">
        <option value="">Primeira captura / inventário sem comparação</option>
        {(history.snapshots || []).map(snapshot => <option key={snapshot.id} value={snapshot.id} disabled={snapshot.status === 'integrity_error'}>{snapshot.label || snapshot.id} · {snapshot.started_at || ''} · {snapshot.status}</option>)}
      </select></label>
      <div className="md:col-span-2 flex flex-wrap items-center gap-3">
        <button disabled={busy} className="px-4 py-2 bg-cyan-800 text-white rounded disabled:opacity-50 flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${busy ? 'animate-spin' : ''}`} />{busy ? 'Capturando evidências...' : 'Capturar e gerar relatório'}</button>
        <button type="button" onClick={() => refresh().catch(error => setError(error.message))} className="px-4 py-2 bg-slate-800 rounded">Atualizar histórico</button>
        {job && <span role="status" className="text-slate-400">Tarefa: {job.status} · {job.id}</span>}
      </div>
    </form>
    <section className="bg-slate-900 border border-slate-700 rounded-xl p-5 space-y-3">
      <div className="flex flex-wrap justify-between gap-3"><h3 className="text-sm font-semibold">Relatórios persistentes</h3><input aria-label="Filtrar relatórios" value={filter} onChange={event => setFilter(event.target.value)} placeholder="Filtrar por ID, analista ou estado" className="p-2 bg-slate-950 border border-slate-700 rounded text-xs min-w-64" /></div>
      <div className="overflow-auto"><table className="w-full text-xs text-left"><thead className="text-slate-400"><tr><th className="p-2">Relatório</th><th className="p-2">Emissão UTC</th><th className="p-2">Analista</th><th className="p-2">Coleta</th><th className="p-2">Abrir</th></tr></thead>
        <tbody>{rows.map(item => <tr key={item.id} className="border-t border-slate-800"><td className="p-2 font-mono break-all">{item.id}</td><td className="p-2">{item.created_at}</td><td className="p-2">{item.analyst}</td><td className="p-2"><span className={item.status !== 'complete' ? 'text-amber-300' : 'text-emerald-300'}>{item.status}</span></td><td className="p-2"><button disabled={loadingReport || item.status === 'integrity_error'} onClick={() => openReport(item.id)} className="px-3 py-1 rounded bg-slate-800 text-cyan-300 flex items-center gap-1"><FileText className="w-3 h-3" />Ver HTML5</button></td></tr>)}</tbody>
      </table>{rows.length === 0 && <p className="text-xs text-slate-500 py-6 text-center">Nenhum relatório. Crie uma captura de referência para começar.</p>}</div>
    </section>
    {report && <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-sm font-semibold">Relatório em tela</h3><div className="flex gap-2 text-xs"><button onClick={() => exportFile('html')} className="px-3 py-2 rounded bg-slate-800 flex items-center gap-2"><Download className="w-3 h-3" />Exportar HTML5</button><button onClick={() => exportFile('json')} className="px-3 py-2 rounded bg-slate-800">Exportar JSON</button></div></div>
      {report.snapshot?.status !== 'complete' && <p className="text-xs text-amber-300 flex gap-2"><AlertTriangle className="w-4 h-4" />Coleta parcial. Consulte a seção de completude antes de interpretar os resultados.</p>}
      <iframe title="Relatório forense HTML5" sandbox="" srcDoc={reportHtml} className="w-full h-[75vh] bg-white border border-slate-700 rounded-xl" />
    </section>}
  </div>;
}
