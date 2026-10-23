import React, { useState, useEffect } from 'react';
import { Server, Network, Cpu, Database, Copy, CheckCircle, RefreshCw, X } from 'lucide-react';

export default function ComputerPropertiesModal({ computerName, onClose, customFetch, showToast }) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState('general'); // 'general' | 'network' | 'ldap'
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadProperties() {
      try {
        setLoading(true);
        const res = await customFetch(`/api/computers/${encodeURIComponent(computerName)}/properties`);
        const json = await res.json();
        if (res.ok && json.data) {
          setData(json.data);
        } else {
          showToast(json.message || 'Falha ao carregar propriedades do computador', 'error');
        }
      } catch (e) {
        showToast('Erro de comunicação ao obter propriedades', 'error');
      } finally {
        setLoading(false);
      }
    }
    loadProperties();
  }, [computerName]);

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
            <Server className="w-5 h-5 text-sky-400" />
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <span>Propriedades da Máquina:</span>
                <span className="font-mono text-sky-300">{computerName}</span>
              </h3>
              <p className="text-[11px] text-slate-400">Atributos Active Directory, Conectividade de Rede e Registro LDB</p>
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
              activeTab === 'general' ? 'border-sky-500 text-sky-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Geral & Identificação</span>
          </button>
          <button
            onClick={() => setActiveTab('network')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'network' ? 'border-sky-500 text-sky-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Rede (IP, MAC, Máscara)</span>
          </button>
          <button
            onClick={() => setActiveTab('ldap')}
            className={`pb-2.5 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'ldap' ? 'border-sky-500 text-sky-400 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
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
              <RefreshCw className="w-6 h-6 animate-spin text-sky-400" />
              <span>Consultando parâmetros e resolução de rede da máquina...</span>
            </div>
          ) : data && (
            <>
              {/* TAB 1: GERAL */}
              {activeTab === 'general' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3 font-mono">
                    <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                      <span className="text-slate-400 text-[11px] block mb-1">Nome NetBIOS:</span>
                      <div className="text-slate-100 font-bold text-sm">{data.hostname}</div>
                    </div>
                    <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                      <span className="text-slate-400 text-[11px] block mb-1">Papel no Domínio:</span>
                      <div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-bold ${
                          data.is_dc ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-slate-800 text-slate-300'
                        }`}>
                          {data.is_dc ? 'Controlador de Domínio (DC)' : 'Estação / Servidor Membro'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2 font-mono">
                    <div>
                      <span className="text-slate-400 text-[11px] block">FQDN (Nome Completo DNS):</span>
                      <div className="text-sky-300 font-bold">{data.fqdn}</div>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[11px] block">Domínio Active Directory / Realm:</span>
                      <div className="text-slate-200">{data.domain}</div>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[11px] block">Distinguished Name (DN):</span>
                      <div className="text-slate-300 text-[11px] break-all">{data.distinguished_name}</div>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1.5">
                    <span className="font-bold text-slate-200 flex items-center gap-1.5 font-sans">
                      <Cpu className="w-3.5 h-3.5 text-sky-400" />
                      <span>Sistema Operacional</span>
                    </span>
                    <div className="text-slate-300 font-mono text-[11px]">
                      {data.operating_system} {data.operating_system_version && `(${data.operating_system_version})`}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-[11px]">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 block">Criado em:</span>
                      <span className="text-slate-300 font-mono">{data.when_created || 'Não registrado'}</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 block">Último Logon:</span>
                      <span className="text-slate-300 font-mono">{data.last_logon || 'Não registrado'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: REDE */}
              {activeTab === 'network' && (
                <div className="space-y-3">
                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-slate-400">Endereço IP (IPv4):</span>
                      <span className="text-emerald-400 font-mono font-bold text-sm bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                        {data.ip_address}
                      </span>
                    </div>

                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-slate-400">Endereço Físico (MAC):</span>
                      <span className="text-cyan-300 font-mono font-bold text-sm bg-cyan-950/60 border border-cyan-800/80 px-2 py-0.5 rounded">
                        {data.mac_address}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Máscara de Rede / Subnet:</span>
                      <span className="text-slate-200 font-mono text-xs bg-slate-900 border border-slate-700 px-2 py-0.5 rounded">
                        {data.netmask}
                      </span>
                    </div>
                  </div>

                  <div className="bg-sky-950/40 border border-sky-800/60 p-3 rounded-xl text-sky-300 text-[11px] space-y-1">
                    <span className="font-bold flex items-center gap-1.5">
                      <CheckCircle className="w-3.5 h-3.5 text-sky-400" />
                      <span>Origem das Informações de Rede</span>
                    </span>
                    <p className="text-slate-300">
                      O endereço IP é resolvido contra as zonas autoritativas do Samba AD DNS. O endereço MAC é obtido através da tabela de vizinhança ARP/IP do kernel local.
                    </p>
                  </div>
                </div>
              )}

              {/* TAB 3: LDAP / LDIF */}
              {activeTab === 'ldap' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Entrada LDAP completa extraída de sam.ldb:</span>
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
