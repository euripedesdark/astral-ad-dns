import React, { useEffect, useState } from 'react';
import RestoreBackupModal from './RestoreBackupModal';

export default function BackupProvisioning({ customFetch, showToast }) {
  const [backups, setBackups] = useState([]);
  const [filename, setFilename] = useState('');
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const refresh = async () => {
    const response = await customFetch('/api/backups');
    const result = await response.json();
    if (!response.ok || !result.success) throw new Error(result.message || 'Falha ao listar backups');
    setBackups(result.data || []);
  };
  useEffect(() => { refresh().catch(error => showToast(error.message, 'error')); }, []);
  const upload = async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 512 * 1024 * 1024) { showToast('Limite de importação: 512 MiB.', 'error'); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('backup', file);
      const response = await customFetch('/api/backups/upload', { method: 'POST', body: form });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.message || 'Falha na importação');
      await refresh();
      setFilename(result.data);
      showToast(result.message);
    } catch (error) { showToast(error.message, 'error'); }
    finally { setBusy(false); event.target.value = ''; }
  };
  return <section className="bg-slate-900 border border-slate-700 rounded-xl p-4 space-y-3 text-xs">
    <h3 className="font-bold text-amber-300">Provisionar / recuperar domínio a partir de backup</h3>
    <p className="text-slate-400">Recupera o domínio completo. Para adicionar uma réplica ao domínio em funcionamento, use o ingresso de DC.</p>
    <label className="block text-slate-300">Importar backup Samba (.tar.bz2 / .tar.gz, até 512 MiB)
      <input type="file" accept=".bz2,.gz" onChange={upload} disabled={busy} className="block mt-2 w-full" />
    </label>
    <select aria-label="Backup para recuperação" value={filename} onChange={event => setFilename(event.target.value)} disabled={busy}
      className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200">
      <option value="">Selecione um backup disponível...</option>
      {backups.map(backup => <option key={backup.filename} value={backup.filename}>{backup.filename} ({backup.size_human})</option>)}
    </select>
    <button onClick={() => setOpen(true)} disabled={busy || !filename} className="px-4 py-2 rounded bg-amber-700 text-white disabled:opacity-50">{busy ? 'Importando...' : 'Configurar recuperação'}</button>
    {open && <RestoreBackupModal filename={filename} onClose={() => setOpen(false)} customFetch={customFetch} showToast={showToast} />}
  </section>;
}
