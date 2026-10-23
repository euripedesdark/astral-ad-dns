import { confirmAction } from './ConfirmationDialog';
import React, { useState, useEffect } from 'react';
import { Sliders, Plus, Trash2, Link, Unlink, RefreshCw, Search, FileText, Image, Terminal, Lock, HardDrive, CheckCircle, X } from 'lucide-react';

export default function GpoTab({ t, showToast, customFetch }) {
  const [gpos, setGpos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);

  // Available OUs for linking
  const [availableOus, setAvailableOus] = useState([]);

  // Form states
  const [displayName, setDisplayName] = useState('');
  const [policyType, setPolicyType] = useState('wallpaper'); // 'wallpaper' | 'command_script' | 'screen_lock' | 'drive_map'
  const [targetOuDn, setTargetOuDn] = useState('');
  const [wallpaperPath, setWallpaperPath] = useState('C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg');
  const [wallpaperStyle, setWallpaperStyle] = useState('Fill');
  const [scriptContent, setScriptContent] = useState('echo GPO Script executado em %DATE% %TIME% >> %TEMP%\\gpo_audit.log');
  const [scriptType, setScriptType] = useState('logon'); // 'logon' | 'startup'
  const [driveLetter, setDriveLetter] = useState('Z:');
  const [driveUncPath, setDriveUncPath] = useState('\\\\srvcloud.cloud\\publico');
  const [screenLockTimeout, setScreenLockTimeout] = useState(15);

  // Link GPO Modal
  const [linkingGpo, setLinkingGpo] = useState(null);
  const [selectedLinkOu, setSelectedLinkOu] = useState('');

  const fetchGpos = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/gpo');
      if (res.ok) {
        const json = await res.json();
        setGpos(json.data || []);
      }
    } catch (e) {
      showToast('Falha ao listar Diretivas de Grupo', 'error');
    } finally {
      setLoading(false);
    }
  };

  const fetchOus = async () => {
    try {
      const res = await customFetch('/api/ou');
      if (res.ok) {
        const json = await res.json();
        setAvailableOus(json.data || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchGpos();
    fetchOus();
  }, []);

  const handleCreateGpo = async (e) => {
    e.preventDefault();
    if (!displayName.trim()) return;

    setCreating(true);
    try {
      const payload = {
        display_name: displayName.trim(),
        policy_type: policyType,
        target_ou_dn: targetOuDn || undefined,
        wallpaper_path: policyType === 'wallpaper' ? wallpaperPath : undefined,
        wallpaper_style: policyType === 'wallpaper' ? wallpaperStyle : undefined,
        script_content: policyType === 'command_script' ? scriptContent : undefined,
        script_type: policyType === 'command_script' ? scriptType : undefined,
        drive_letter: policyType === 'drive_map' ? driveLetter : undefined,
        drive_unc_path: policyType === 'drive_map' ? driveUncPath : undefined,
        screen_lock_timeout_mins: policyType === 'screen_lock' ? parseInt(screenLockTimeout, 10) : undefined,
      };

      const res = await customFetch('/api/gpo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Diretiva de Grupo criada com sucesso!');
        setShowCreateModal(false);
        setDisplayName('');
        fetchGpos();
      } else {
        showToast(data.message || 'Erro ao criar GPO', 'error');
      }
    } catch (err) {
      showToast('Erro de comunicação com o servidor', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteGpo = async (gpo) => {
    const isDefault = gpo.guid.toUpperCase().includes('31B2F340') || gpo.guid.toUpperCase().includes('6AC1786C');
    if (isDefault) {
      showToast('Não é permitido excluir diretivas padrão do Active Directory', 'error');
      return;
    }
    if (!await confirmAction(`Deseja realmente excluir a Diretiva '${gpo.display_name}' (${gpo.guid})?`)) {
      return;
    }

    try {
      const res = await customFetch(`/api/gpo/${encodeURIComponent(gpo.guid)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'GPO excluída com sucesso');
        fetchGpos();
      } else {
        showToast(data.message || 'Erro ao excluir GPO', 'error');
      }
    } catch (e) {
      showToast('Erro ao excluir GPO', 'error');
    }
  };

  const handleLinkGpo = async (e) => {
    e.preventDefault();
    if (!linkingGpo || !selectedLinkOu) return;

    try {
      const res = await customFetch(`/api/gpo/${encodeURIComponent(linkingGpo.guid)}/link`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_dn: selectedLinkOu })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'GPO vinculada com sucesso!');
        setLinkingGpo(null);
        setSelectedLinkOu('');
        fetchGpos();
      } else {
        showToast(data.message || 'Erro ao vincular GPO', 'error');
      }
    } catch (err) {
      showToast('Erro ao vincular GPO', 'error');
    }
  };

  const handleUnlinkGpo = async (guid, containerDn) => {
    if (!await confirmAction(`Remover vínculo da política com '${containerDn}'?`)) return;

    try {
      const res = await customFetch(`/api/gpo/${encodeURIComponent(guid)}/link/${encodeURIComponent(containerDn)}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Vínculo removido com sucesso');
        fetchGpos();
      } else {
        showToast(data.message || 'Erro ao remover vínculo', 'error');
      }
    } catch (e) {
      showToast('Erro ao remover vínculo', 'error');
    }
  };

  const filtered = gpos.filter(g => 
    g.display_name.toLowerCase().includes(search.toLowerCase()) || 
    g.guid.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filtrar Políticas de Grupo (GPOs)..."
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchGpos}
            className="p-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg text-slate-300 transition"
            title="Recarregar"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md"
          >
            <Plus className="w-4 h-4" />
            <span>Criar Diretiva (GPO)</span>
          </button>
        </div>
      </div>

      {/* GPO Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {filtered.map((gpo) => {
          const isDefault = gpo.guid.toUpperCase().includes('31B2F340') || gpo.guid.toUpperCase().includes('6AC1786C');
          return (
            <div
              key={gpo.guid}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 shadow-sm flex flex-col justify-between transition space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                    isDefault ? 'bg-amber-950 text-amber-400 border border-amber-800' : 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                  }`}>
                    <Sliders className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                      <span>{gpo.display_name}</span>
                      {isDefault && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
                          Padrão
                        </span>
                      )}
                    </h4>
                    <span className="text-[10px] text-slate-400 font-mono block break-all">
                      {gpo.guid}
                    </span>
                  </div>
                </div>

                {!isDefault && (
                  <button
                    onClick={() => handleDeleteGpo(gpo)}
                    className="text-slate-500 hover:text-rose-400 p-1 rounded transition"
                    title="Excluir GPO"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Linked Containers */}
              <div className="space-y-1.5 pt-1">
                <span className="text-[11px] text-slate-400 font-semibold block">Vínculos de Aplicação (OUs):</span>
                {gpo.linked_containers && gpo.linked_containers.length > 0 ? (
                  <div className="space-y-1">
                    {gpo.linked_containers.map((c, idx) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800/80 px-2 py-1 rounded flex items-center justify-between text-[10px] font-mono">
                        <span className="text-emerald-300 truncate max-w-[85%]">{c}</span>
                        <button
                          onClick={() => handleUnlinkGpo(gpo.guid, c)}
                          className="text-slate-500 hover:text-rose-400"
                          title="Desvincular"
                        >
                          <Unlink className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-[10px] text-slate-500 italic block">
                    Nenhum container vinculado (política não aplicada a nenhuma OU).
                  </span>
                )}
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-[10px] text-slate-500 font-mono">Versão: {gpo.version}</span>
                <button
                  onClick={() => setLinkingGpo(gpo)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium transition flex items-center gap-1"
                >
                  <Link className="w-3 h-3 text-indigo-400" />
                  <span>Vincular a OU</span>
                </button>
              </div>
            </div>
          );
        })}

        {filtered.length === 0 && !loading && (
          <div className="col-span-full py-8 text-center text-slate-500 text-xs">
            Nenhuma Diretiva de Grupo (GPO) encontrada.
          </div>
        )}
      </div>

      {/* Modal: Criar Nova GPO */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-xl w-full shadow-2xl space-y-4 text-xs overflow-y-auto max-h-[90vh]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-indigo-400" />
                <span>Criar Nova Diretiva de Grupo (GPO)</span>
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateGpo} className="space-y-4">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Nome de Exibição da GPO *</label>
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="ex: Politica_PapelDeParede_Corporativo"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono focus:border-indigo-500 focus:outline-none"
                />
              </div>

              {/* Template Selector */}
              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Modelo / Tipo de Política Simples *</label>
                <div className="grid grid-cols-2 gap-2">
                  <label
                    onClick={() => setPolicyType('wallpaper')}
                    className={`p-2.5 rounded-xl border cursor-pointer transition flex items-center gap-2 ${
                      policyType === 'wallpaper' ? 'bg-indigo-950/80 border-indigo-500 text-white font-bold' : 'bg-slate-950 border-slate-800 text-slate-300'
                    }`}
                  >
                    <Image className="w-4 h-4 text-sky-400" />
                    <span>Papel de Parede</span>
                  </label>

                  <label
                    onClick={() => setPolicyType('command_script')}
                    className={`p-2.5 rounded-xl border cursor-pointer transition flex items-center gap-2 ${
                      policyType === 'command_script' ? 'bg-indigo-950/80 border-indigo-500 text-white font-bold' : 'bg-slate-950 border-slate-800 text-slate-300'
                    }`}
                  >
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span>Executar Comandos</span>
                  </label>

                  <label
                    onClick={() => setPolicyType('screen_lock')}
                    className={`p-2.5 rounded-xl border cursor-pointer transition flex items-center gap-2 ${
                      policyType === 'screen_lock' ? 'bg-indigo-950/80 border-indigo-500 text-white font-bold' : 'bg-slate-950 border-slate-800 text-slate-300'
                    }`}
                  >
                    <Lock className="w-4 h-4 text-amber-400" />
                    <span>Bloqueio de Tela</span>
                  </label>

                  <label
                    onClick={() => setPolicyType('drive_map')}
                    className={`p-2.5 rounded-xl border cursor-pointer transition flex items-center gap-2 ${
                      policyType === 'drive_map' ? 'bg-indigo-950/80 border-indigo-500 text-white font-bold' : 'bg-slate-950 border-slate-800 text-slate-300'
                    }`}
                  >
                    <HardDrive className="w-4 h-4 text-indigo-400" />
                    <span>Mapear Unidade</span>
                  </label>
                </div>
              </div>

              {/* Template: Wallpaper */}
              {policyType === 'wallpaper' && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-3">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Caminho da Imagem do Papel de Parede</label>
                    <input
                      type="text"
                      value={wallpaperPath}
                      onChange={(e) => setWallpaperPath(e.target.value)}
                      placeholder="C:\Windows\Web\Wallpaper\Windows\img0.jpg ou \\srvcloud.cloud\sysvol\..."
                      className="w-full bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-lg text-slate-100 font-mono text-[11px] focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Ajuste do Papel de Parede</label>
                    <select
                      value={wallpaperStyle}
                      onChange={(e) => setWallpaperStyle(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-lg text-slate-100 text-xs focus:border-indigo-500 focus:outline-none"
                    >
                      <option value="Fill">Preencher (Fill)</option>
                      <option value="Fit">Ajustar (Fit)</option>
                      <option value="Stretch">Esticar (Stretch)</option>
                      <option value="Center">Centralizado (Center)</option>
                      <option value="Tile">Lado a Lado (Tile)</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Template: Command Script */}
              {policyType === 'command_script' && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-3">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Momento da Execução</label>
                    <div className="flex gap-4">
                      <label className="flex items-center gap-1.5 cursor-pointer text-slate-200">
                        <input
                          type="radio"
                          checked={scriptType === 'logon'}
                          onChange={() => setScriptType('logon')}
                        />
                        <span>No Logon do Usuário</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer text-slate-200">
                        <input
                          type="radio"
                          checked={scriptType === 'startup'}
                          onChange={() => setScriptType('startup')}
                        />
                        <span>Na Inicialização da Máquina (Startup)</span>
                      </label>
                    </div>
                  </div>
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Comandos em Lote / Script Batch</label>
                    <textarea
                      rows={4}
                      value={scriptContent}
                      onChange={(e) => setScriptContent(e.target.value)}
                      placeholder="Comandos a executar em lote (.bat)"
                      className="w-full bg-slate-900 border border-slate-700 p-2.5 rounded-lg text-emerald-300 font-mono text-[11px] focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Template: Screen Lock */}
              {policyType === 'screen_lock' && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-3">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Tempo Limite de Inatividade (Minutos)</label>
                    <input
                      type="number"
                      min={1}
                      max={120}
                      value={screenLockTimeout}
                      onChange={(e) => setScreenLockTimeout(e.target.value)}
                      className="w-32 bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-lg text-slate-100 font-mono text-xs focus:border-indigo-500 focus:outline-none"
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">
                      A tela será bloqueada com solicitação obrigatória de senha após o período selecionado.
                    </span>
                  </div>
                </div>
              )}

              {/* Template: Drive Map */}
              {policyType === 'drive_map' && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-3">
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-slate-300 font-medium mb-1">Letra da Unidade</label>
                      <input
                        type="text"
                        value={driveLetter}
                        onChange={(e) => setDriveLetter(e.target.value.toUpperCase())}
                        placeholder="Z:"
                        className="w-full bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-lg text-slate-100 font-mono text-xs focus:border-indigo-500 focus:outline-none"
                      />
                    </div>
                    <div className="col-span-2">
                      <label className="block text-slate-300 font-medium mb-1">Caminho UNC da Pasta</label>
                      <input
                        type="text"
                        value={driveUncPath}
                        onChange={(e) => setDriveUncPath(e.target.value)}
                        placeholder="\\srvcloud.cloud\publico"
                        className="w-full bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-lg text-slate-100 font-mono text-xs focus:border-indigo-500 focus:outline-none"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Target OU linking */}
              <div>
                <label className="block text-slate-300 font-medium mb-1">Vincular Automaticamente a uma OU (Opcional)</label>
                <select
                  value={targetOuDn}
                  onChange={(e) => setTargetOuDn(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono text-[11px] focus:border-indigo-500 focus:outline-none"
                >
                  <option value="">Não vincular agora (Vincular manualmente depois)</option>
                  {availableOus.map((o) => (
                    <option key={o.dn} value={o.dn}>
                      {o.dn}
                    </option>
                  ))}
                </select>
              </div>

              <div className="pt-2 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold flex items-center gap-1.5 shadow"
                >
                  {creating && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{creating ? 'Criando Diretiva...' : 'Criar e Ativar GPO'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Vincular GPO a OU */}
      {linkingGpo && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Link className="w-4 h-4 text-indigo-400" />
                <span>Vincular GPO: {linkingGpo.display_name}</span>
              </h3>
              <button onClick={() => setLinkingGpo(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleLinkGpo} className="space-y-3">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Selecione a Unidade Organizacional (OU) *</label>
                <select
                  required
                  value={selectedLinkOu}
                  onChange={(e) => setSelectedLinkOu(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono text-[11px] focus:border-indigo-500 focus:outline-none"
                >
                  <option value="">Selecione uma OU...</option>
                  {availableOus.map((o) => (
                    <option key={o.dn} value={o.dn}>
                      {o.dn}
                    </option>
                  ))}
                </select>
              </div>

              <div className="pt-2 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setLinkingGpo(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={!selectedLinkOu}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold"
                >
                  Vincular Política
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
