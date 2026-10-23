import { confirmAction } from './ConfirmationDialog';
import React, { useState, useEffect } from 'react';
import { FolderTree, Plus, Trash2, RefreshCw, Search, Users, Server, Layers, X, CheckCircle, AlertTriangle } from 'lucide-react';

export default function OUTab({ t, showToast, customFetch }) {
  const [ous, setOus] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newOuName, setNewOuName] = useState('');
  const [newOuParent, setNewOuParent] = useState('');
  const [newOuDesc, setNewOuDesc] = useState('');
  const [creating, setCreating] = useState(false);

  // Objects inside OU Modal
  const [selectedOuObjects, setSelectedOuObjects] = useState(null);
  const [ouObjectsList, setOuObjectsList] = useState([]);
  const [loadingObjects, setLoadingObjects] = useState(false);

  const fetchOus = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/ou');
      if (res.ok) {
        const json = await res.json();
        setOus(json.data || []);
      }
    } catch (e) {
      showToast('Falha ao listar Unidades Organizacionais', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOus();
  }, []);

  const handleCreateOu = async (e) => {
    e.preventDefault();
    if (!newOuName.trim()) return;

    setCreating(true);
    try {
      const res = await customFetch('/api/ou', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newOuName.trim(),
          parent_dn: newOuParent.trim() || undefined,
          description: newOuDesc.trim() || undefined,
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Unidade Organizacional criada com sucesso!');
        setShowCreateModal(false);
        setNewOuName('');
        setNewOuParent('');
        setNewOuDesc('');
        fetchOus();
      } else {
        showToast(data.message || 'Erro ao criar OU', 'error');
      }
    } catch (err) {
      showToast('Erro de comunicação com o servidor', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteOu = async (ou) => {
    if (ou.is_system) {
      showToast('Não é permitido excluir a OU de sistema Domain Controllers', 'error');
      return;
    }
    const recursive = await confirmAction(`Excluir também todos os objetos dentro de '${ou.name}'?\n\nEscolha como prosseguir.`, { confirmLabel: 'Excluir conteúdo também', cancelLabel: 'Somente OU vazia' });
    if (!await confirmAction(`Confirmar exclusão ${recursive ? 'da OU e TODOS os seus objetos' : 'somente da OU vazia'}?\n\nDN: ${ou.dn}`)) return;

    try {
      const res = await customFetch(`/api/ou/${encodeURIComponent(ou.dn)}?recursive=${recursive}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'OU excluída com sucesso');
        fetchOus();
      } else {
        showToast(data.message || 'Erro ao excluir OU', 'error');
      }
    } catch (e) {
      showToast('Erro de comunicação ao excluir OU', 'error');
    }
  };

  const handleViewObjects = async (ou) => {
    setSelectedOuObjects(ou);
    setLoadingObjects(true);
    try {
      const res = await customFetch(`/api/ou/${encodeURIComponent(ou.dn)}/objects`);
      const json = await res.json();
      if (res.ok) {
        setOuObjectsList(json.data || []);
      } else {
        setOuObjectsList([]);
      }
    } catch (e) {
      showToast('Erro ao carregar objetos da OU', 'error');
    } finally {
      setLoadingObjects(false);
    }
  };

  const filtered = ous.filter(o => 
    o.name.toLowerCase().includes(search.toLowerCase()) || 
    o.dn.toLowerCase().includes(search.toLowerCase())
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
            placeholder="Filtrar Unidades Organizacionais (OUs)..."
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchOus}
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
            <span>Nova Unidade Organizacional (OU)</span>
          </button>
        </div>
      </div>

      {/* OU Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map((ou) => (
          <div
            key={ou.dn}
            className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 shadow-sm flex flex-col justify-between transition space-y-3"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                  ou.is_system ? 'bg-amber-950/80 text-amber-400 border border-amber-800' : 'bg-indigo-950/80 text-indigo-400 border border-indigo-800'
                }`}>
                  <FolderTree className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-1.5">
                    <span>{ou.name}</span>
                    {ou.is_system && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
                        Sistema
                      </span>
                    )}
                  </h4>
                  <span className="text-[10px] text-slate-400 block break-all font-mono">
                    {ou.dn}
                  </span>
                </div>
              </div>

              {!ou.is_system && (
                <button
                  onClick={() => handleDeleteOu(ou)}
                  className="text-slate-500 hover:text-rose-400 p-1 rounded transition"
                  title="Excluir OU"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-sans">
              <button
                onClick={() => handleViewObjects(ou)}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition flex items-center gap-1"
              >
                <Layers className="w-3 h-3 text-indigo-400" />
                <span>Ver Objetos da OU</span>
              </button>
            </div>
          </div>
        ))}

        {filtered.length === 0 && !loading && (
          <div className="col-span-full py-8 text-center text-slate-500 text-xs">
            Nenhuma Unidade Organizacional encontrada. Clique em "+ Nova Unidade Organizacional (OU)" para criar uma.
          </div>
        )}
      </div>

      {/* Modal: Criar Nova OU */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FolderTree className="w-4 h-4 text-indigo-400" />
                <span>Criar Nova Unidade Organizacional (OU)</span>
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateOu} className="space-y-3">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Nome da OU *</label>
                <input
                  type="text"
                  required
                  value={newOuName}
                  onChange={(e) => setNewOuName(e.target.value)}
                  placeholder="ex: Financeiro, RH, Tecnologia, Filial-SP"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">OU Pai / Container de Destino</label>
                <select
                  value={newOuParent}
                  onChange={(e) => setNewOuParent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono text-[11px] focus:border-indigo-500 focus:outline-none"
                >
                  <option value="">Raiz do Domínio (Padrão)</option>
                  {ous.map((o) => (
                    <option key={o.dn} value={o.dn}>
                      {o.dn}
                    </option>
                  ))}
                </select>
                <span className="text-[10px] text-slate-400 mt-0.5 block">
                  Permite aninhar a nova OU dentro de uma unidade existente ou deixá-la na raiz do domínio.
                </span>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Descrição (Opcional)</label>
                <input
                  type="text"
                  value={newOuDesc}
                  onChange={(e) => setNewOuDesc(e.target.value)}
                  placeholder="ex: Unidade dos departamentos de Tecnologia"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
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
                  <span>{creating ? 'Criando OU...' : 'Criar Unidade'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Objetos da OU */}
      {selectedOuObjects && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden flex flex-col max-h-[80vh] text-xs">
            <div className="bg-slate-950 px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FolderTree className="w-4 h-4 text-indigo-400" />
                <div>
                  <h4 className="font-bold text-white">Objetos em: {selectedOuObjects.name}</h4>
                  <span className="text-[10px] text-slate-400 font-mono">{selectedOuObjects.dn}</span>
                </div>
              </div>
              <button onClick={() => setSelectedOuObjects(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-2 flex-1">
              {loadingObjects ? (
                <div className="py-8 text-center text-slate-400 flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                  <span>Listando objetos da OU...</span>
                </div>
              ) : ouObjectsList.length > 0 ? (
                <div className="space-y-1.5">
                  {ouObjectsList.map((obj, i) => (
                    <div key={i} className="bg-slate-950 border border-slate-800/80 p-2.5 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {obj.object_type === 'Computer' ? (
                          <Server className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                        ) : obj.object_type === 'User/Group' ? (
                          <Users className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        ) : (
                          <Layers className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        )}
                        <span className="font-mono text-slate-200 font-bold">{obj.name}</span>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {obj.object_type}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-slate-500">
                  Nenhum objeto alocado diretamente nesta Unidade Organizacional.
                </div>
              )}
            </div>

            <div className="bg-slate-950 px-5 py-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedOuObjects(null)}
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
