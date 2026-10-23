import React, { useState, useEffect } from 'react';
import { User, Shield, Key, Database, Copy, CheckCircle, RefreshCw, X, AlertCircle } from 'lucide-react';

export default function UserPropertiesModal({ username, onClose, customFetch, showToast }) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState('general'); // 'general' | 'permissions' | 'groups' | 'ldap'
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadProperties() {
      try {
        setLoading(true);
        const res = await customFetch(`/api/users/${encodeURIComponent(username)}/properties`);
        const json = await res.json();
        if (res.ok && json.data) {
          setData(json.data);
        } else {
          showToast(json.message || 'Falha ao carregar propriedades do usuário', 'error');
        }
      } catch (e) {
        showToast('Erro ao obter propriedades do usuário', 'error');
      } finally {
        setLoading(false);
      }
    }
    loadProperties();
  }, [username]);

  const handleCopyLdif = () => {
    if (data?.raw_ldif) {
      navigator.clipboard.writeText(data.raw_ldif);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      showToast('Registro LDAP copiado para a área de transferência');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <User className="w-5 h-5 text-indigo-400" />
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <span>Propriedades do Usuário:</span>
                <span className="font-mono text-indigo-300">{username}</span>
              </h3>
              <p className="text-[11px] text-slate-400">Permissões de Conta, Grupos e Formato LDAP do Active Directory</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="bg-slate-900/60 px-6 pt-3 border-b border-slate-800/80 flex items-center gap-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab('general')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'general' ? 'border-indigo-500 text-indigo-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <User className="w-3.5 h-3.5" />
            <span>Geral</span>
          </button>
          <button
            onClick={() => setActiveTab('permissions')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'permissions' ? 'border-indigo-500 text-indigo-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Permissões & Flags</span>
          </button>
          <button
            onClick={() => setActiveTab('groups')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'groups' ? 'border-indigo-500 text-indigo-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>Membros de Grupos ({data?.groups?.length || 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('ldap')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'ldap' ? 'border-indigo-500 text-indigo-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Entrada LDAP (LDIF)</span>
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs flex-1">
          {loading ? (
            <div className="text-center py-12 text-slate-400 flex flex-col items-center justify-center gap-2">
              <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
              <span>Consultando atributos do usuário no Active Directory...</span>
            </div>
          ) : data && (
            <>
              {/* TAB 1: GERAL */}
              {activeTab === 'general' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                      <span className="text-slate-400 text-[11px] block">Nome de Usuário (sAMAccountName):</span>
                      <div className="text-slate-100 font-bold font-mono text-sm mt-0.5">{data.username}</div>
                    </div>
                    <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                      <span className="text-slate-400 text-[11px] block">Nome de Exibição (displayName):</span>
                      <div className="text-slate-200 font-semibold mt-0.5">{data.display_name || data.username}</div>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2 font-mono">
                    <div>
                      <span className="text-slate-400 text-[11px] block">Distinguished Name (DN):</span>
                      <div className="text-slate-300 text-[11px] break-all">{data.distinguished_name}</div>
                    </div>
                    {data.mail && (
                      <div>
                        <span className="text-slate-400 text-[11px] block">E-mail:</span>
                        <div className="text-indigo-300">{data.mail}</div>
                      </div>
                    )}
                    {data.description && (
                      <div>
                        <span className="text-slate-400 text-[11px] block">Descrição:</span>
                        <div className="text-slate-300">{data.description}</div>
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 block">Criado em:</span>
                      <span className="text-slate-300 font-mono">{data.when_created || 'Não registrado'}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 block">Modificado em:</span>
                      <span className="text-slate-300 font-mono">{data.when_changed || 'Não registrado'}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 block">Tentativas Inválidas:</span>
                      <span className="text-slate-300 font-mono">{data.bad_pwd_count}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: PERMISSÕES & POLÍTICAS */}
              {activeTab === 'permissions' && (
                <div className="space-y-3">
                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                    <span className="font-bold text-slate-200 text-xs block mb-2">Permissões Efetivas do Active Directory:</span>
                    <div className="space-y-2">
                      {data.permissions_summary.map((perm, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-slate-200 text-xs bg-slate-900/80 px-3 py-2 rounded-lg border border-slate-800">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span>{perm}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[11px]">UserAccountControl (UAC):</span>
                      <span className="font-mono font-bold text-indigo-300">{data.user_account_control} (0x{data.user_account_control.toString(16).toUpperCase()})</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Privilégio Administrativo:</span>
                      <span className={`font-bold ${data.is_admin ? 'text-amber-400' : 'text-slate-400'}`}>
                        {data.is_admin ? 'Sim (Administrador)' : 'Não (Usuário Padrão)'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: GRUPOS */}
              {activeTab === 'groups' && (
                <div className="space-y-2">
                  <span className="text-slate-400 text-[11px] block">Grupos dos quais {data.username} é membro:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {data.groups.map((grp, idx) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 p-2.5 rounded-lg flex items-center justify-between text-xs">
                        <span className="font-mono text-slate-200">{grp}</span>
                        {grp.toLowerCase().includes('admin') && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 text-[10px] font-bold border border-amber-800">
                            Admin
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 4: ENTRADA LDAP */}
              {activeTab === 'ldap' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Registro LDAP completo extraído de sam.ldb:</span>
                    <button
                      onClick={handleCopyLdif}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-medium flex items-center gap-1 transition"
                    >
                      {copied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copied ? 'Copiado!' : 'Copiar LDIF'}</span>
                    </button>
                  </div>

                  <pre className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-[11px] font-mono text-emerald-300/90 overflow-x-auto max-h-72 whitespace-pre-wrap select-all">
                    {data.raw_ldif || '# Nenhum registro retornado pelo ldbsearch'}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-950 px-6 py-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
}
