import React, { useState } from 'react';
import { confirmAction } from './ConfirmationDialog';

export default function DemoteControllerModal({ computer, customFetch, showToast, onClose, onSuccess }) {
  const [username, setUsername] = useState('administrator');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [demotionError, setDemotionError] = useState('');
  const submit = async event => {
    event.preventDefault();
    if (!await confirmAction(`Despromover o DC secundário ${computer.name}? Ele deixará de replicar o domínio. O DC primário e servidores com funções FSMO estão protegidos.`)) return;
    setBusy(true);
    setDemotionError('');
    try {
      const response = await customFetch(`/api/computers/${encodeURIComponent(computer.name)}/demote`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ admin_username: username, admin_password: password }),
      });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.message || 'Despromoção falhou');
      setPassword('');
      showToast(result.message);
      onSuccess();
      onClose();
    } catch (error) {
      const message = error?.message || 'Falha desconhecida na despromoção';
      setDemotionError(message);
      showToast('Falha na despromoção. Consulte o diagnóstico no formulário.', 'error');
    }
    finally { setBusy(false); }
  };
  return <div className="fixed inset-0 z-50 bg-slate-950/90 flex items-center justify-center p-4">
    <form onSubmit={submit} role="dialog" aria-modal="true" aria-label="Despromover DC secundário" className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 text-xs space-y-4">
      <h3 className="font-bold text-amber-300">Despromover DC secundário: {computer.name}</h3>
      <p className="text-slate-400">No DC remoto, é necessário acesso administrativo SSH por chave já configurado. A identidade do servidor e suas funções FSMO serão verificadas antes da operação.</p>
      <label className="block">Administrador do domínio<input required value={username} onChange={event => setUsername(event.target.value)} className="block w-full p-2 bg-slate-950 border border-slate-700 rounded mt-1" /></label>
      <label className="block">Senha do domínio<input required type="password" autoComplete="off" value={password} onChange={event => setPassword(event.target.value)} className="block w-full p-2 bg-slate-950 border border-slate-700 rounded mt-1" /></label>
      {demotionError && (
        <div role="alert" className="rounded-lg border border-rose-700 bg-rose-950/60 p-3 space-y-2">
          <p className="font-semibold text-rose-200">A despromoção não foi confirmada</p>
          <pre className="whitespace-pre-wrap break-words max-h-52 overflow-y-auto text-rose-100 select-text">{demotionError}</pre>
          <button type="button" className="rounded bg-rose-900 px-3 py-1.5 text-rose-100 hover:bg-rose-800"
            onClick={() => navigator.clipboard?.writeText(`Falha na despromoção de ${computer.name}: ${demotionError}`)}>
            Copiar diagnóstico
          </button>
          <p className="text-rose-300/80">Verifique o estado do DC antes de tentar novamente.</p>
        </div>
      )}
      <div className="flex justify-end gap-3"><button type="button" disabled={busy} onClick={onClose} className="px-4 py-2 rounded bg-slate-800">Cancelar</button>
        <button disabled={busy || !password} className="px-4 py-2 rounded bg-amber-700 text-white disabled:opacity-50">{busy ? 'Despromovendo...' : 'Despromover secundário'}</button></div>
    </form>
  </div>;
}
