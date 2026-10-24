import React, { useState } from 'react';
import { confirmAction } from './ConfirmationDialog';

export default function ControllerTransitionModal({ computer, action, customFetch, showToast, onClose, onSuccess }) {
  const primary = action === 'promote_primary';
  const title = primary ? 'Promover secundário a principal' : 'Converter RODC em DC gravável secundário';
  const [username, setUsername] = useState('administrator');
  const [password, setPassword] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [steps, setSteps] = useState([]);
  const [error, setError] = useState('');
  const [completed, setCompleted] = useState(false);
  const submit = async dryRun => {
    if (!dryRun && !await confirmAction(primary
      ? `Transferir as sete funções FSMO para ${computer.name}? O antigo principal continuará no domínio como DC gravável secundário.`
      : `Despromover e ingressar novamente ${computer.name} como DC gravável? O serviço ficará indisponível durante a conversão. Se o novo ingresso falhar, a base RODC antiga permanecerá parada.`)) return;
    setBusy(true); setError(''); setSteps([]);
    try {
      const response = await customFetch(`/api/computers/${encodeURIComponent(computer.name)}/transition`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, admin_username: username, admin_password: password, dry_run: dryRun, rejoin_confirmed: confirmed }),
      });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.message || 'Transição falhou');
      setSteps(result.data || []);
      showToast(result.message);
      if (!dryRun) { setCompleted(true); setPassword(''); onSuccess(); }
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  };
  return <div className="fixed inset-0 z-50 bg-slate-950/90 flex items-center justify-center p-4">
    <section role="dialog" aria-modal="true" aria-label={title} className="max-w-xl w-full max-h-[90vh] overflow-auto p-6 rounded-xl bg-slate-900 border border-slate-700 text-xs space-y-4">
      <h3 className="font-bold text-cyan-300">{title}: {computer.name}</h3>
      <p className="text-slate-300">{primary
        ? 'Verifica replicação e transfere as funções FSMO, deixando PDC por último. O antigo principal permanece ativo como secundário.'
        : 'Cria backup no parceiro gravável, preserva a réplica local e faz novo ingresso com SAMBA_INTERNAL. O SYSVOL é sincronizado do parceiro.'}</p>
      <p className="text-slate-400">No DC remoto, configure acesso SSH por chave e host conhecido. Use credenciais com permissão para administrar o domínio e suas funções FSMO.</p>
      {!completed && <>
        <label className="block">Administrador do domínio<input value={username} onChange={event => setUsername(event.target.value)} disabled={busy} className="block mt-1 w-full p-2 bg-slate-950 border border-slate-700 rounded" /></label>
        <label className="block">Senha<input type="password" autoComplete="off" value={password} onChange={event => setPassword(event.target.value)} disabled={busy} className="block mt-1 w-full p-2 bg-slate-950 border border-slate-700 rounded" /></label>
        {!primary && <label className="flex gap-2 text-amber-300"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy} />Confirmo a interrupção e o novo ingresso do RODC. Em caso de falha após a despromoção, será necessário retomar o ingresso.</label>}
      </>}
      {error && <p role="alert" className="text-rose-300 whitespace-pre-wrap break-words">{error}</p>}
      {steps.length > 0 && <ul className="space-y-2 text-emerald-300">{steps.map((step, index) => <li key={index}>{step}</li>)}</ul>}
      <div className="flex flex-wrap justify-end gap-3">
        <button disabled={busy} onClick={onClose} className="px-4 py-2 bg-slate-800 rounded">{completed ? 'Concluir' : 'Cancelar'}</button>
        {!completed && <><button disabled={busy || !username || !password} onClick={() => submit(true)} className="px-4 py-2 bg-slate-700 rounded disabled:opacity-50">Validar plano</button>
          <button disabled={busy || !username || !password || (!primary && !confirmed)} onClick={() => submit(false)} className="px-4 py-2 bg-cyan-800 rounded disabled:opacity-50">{busy ? 'Executando...' : 'Executar transição'}</button></>}
      </div>
    </section>
  </div>;
}
