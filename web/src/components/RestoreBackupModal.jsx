import { confirmAction } from './ConfirmationDialog';
import React, { useState } from 'react';
import { RotateCcw, AlertTriangle, CheckCircle, RefreshCw, X, ShieldCheck } from 'lucide-react';

export default function RestoreBackupModal({ filename, onClose, customFetch, showToast, onSuccess }) {
  const [dryRun, setDryRun] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [steps, setSteps] = useState([]);
  const [errorMsg, setErrorMsg] = useState(null);
  const [completed, setCompleted] = useState(false);

  const handleExecuteRestore = async () => {
    if (!dryRun && !await confirmAction(`ATENÇÃO: Deseja restaurar o backup do Samba AD '${filename}'? Os bancos LDB e Sysvol do Samba serão restaurados, preservando o IP e configurações de rede atuais da máquina.`)) {
      return;
    }

    setRestoring(true);
    setSteps([]);
    setErrorMsg(null);

    try {
      const res = await customFetch('/api/backups/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename,
          dry_run: dryRun,
        })
      });
      const data = await res.json();
      if (res.ok) {
        setSteps(data.data || []);
        setCompleted(true);
        showToast(data.message);
        if (!dryRun && onSuccess) {
          onSuccess();
        }
      } else {
        setErrorMsg(data.message || 'Falha ao restaurar backup');
        setSteps(data.data || []);
      }
    } catch (e) {
      setErrorMsg('Erro de comunicação com o servidor');
    } finally {
      setRestoring(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <RotateCcw className="w-5 h-5 text-amber-400" />
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">Restauração de Backup do Samba AD</h3>
              <p className="text-[11px] text-slate-400">Recuperação de banco LDB, Kerberos e Sysvol</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4 text-xs">
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono">
            <span className="text-slate-400 text-[11px] block">Arquivo de Backup Selecionado:</span>
            <span className="text-amber-300 font-bold break-all text-xs">{filename}</span>
          </div>

          {/* Regra de Preservação de Rede */}
          <div className="bg-emerald-950/40 border border-emerald-800/60 p-3.5 rounded-xl text-emerald-300 space-y-1 text-[11px]">
            <span className="font-bold flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Garantia de Preservação de Rede</span>
            </span>
            <p className="text-slate-300 leading-relaxed">
              A restauração atua <strong>exclusivamente sobre os componentes do Samba Active Directory</strong> (banco sam.ldb, segredos, Kerberos e Sysvol). O endereço IP do servidor, rotas e interfaces de rede do host são <strong>integralmente preservados</strong>.
            </p>
          </div>

          {!completed && (
            <div className="space-y-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                <input
                  type="checkbox"
                  checked={dryRun}
                  onChange={(e) => setDryRun(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-700 text-indigo-600"
                />
                <span className="font-medium text-indigo-300">Modo de Simulação Preventiva (Dry-Run)</span>
              </label>

              {errorMsg && (
                <div className="p-3 bg-rose-950/80 border border-rose-800 rounded-lg text-rose-200 font-mono text-[11px]">
                  {errorMsg}
                </div>
              )}

              <button
                type="button"
                onClick={handleExecuteRestore}
                disabled={restoring}
                className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg font-bold text-xs shadow-lg transition flex items-center justify-center gap-2"
              >
                {restoring ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
                <span>{restoring ? 'Restaurando Base do Samba AD...' : (dryRun ? 'Simular Restauração' : 'Executar Restauração do Samba AD')}</span>
              </button>
            </div>
          )}

          {steps.length > 0 && (
            <div className="space-y-2 pt-2">
              <span className="font-bold text-slate-300 text-[11px]">Relatório de Execução:</span>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5 font-mono text-[11px] max-h-48 overflow-y-auto">
                {steps.map((st, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-emerald-400">
                    <CheckCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{st}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-950 px-6 py-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
          >
            {completed ? 'Concluir' : 'Cancelar'}
          </button>
        </div>
      </div>
    </div>
  );
}
