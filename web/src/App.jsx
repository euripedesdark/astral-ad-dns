import React, { useState, useEffect } from 'react';
import { translations } from './i18n';
import { 
  Server, Shield, Globe, Users, Network, Activity, 
  Database, RefreshCw, Key, CheckCircle, XCircle, AlertTriangle, 
  Search, Plus, Trash2, Edit3, ArrowRight, Copy, Terminal, 
  ExternalLink, Layers, Cpu, Lock, HardDrive, HelpCircle, User, LogOut, Heart,
  FolderTree, Sliders, FileText, RotateCcw, MoreVertical, Info
} from 'lucide-react';
import DonationModal from './components/DonationModal';
import ComputerPropertiesModal from './components/ComputerPropertiesModal';
import UserPropertiesModal from './components/UserPropertiesModal';
import RestoreBackupModal from './components/RestoreBackupModal';
import OUTab from './components/OUTab';
import ConfirmationDialog, { confirmAction } from './components/ConfirmationDialog';
import GpoTab from './components/GpoTab';
import ForensicsTab from './components/ForensicsTab';
import BackupProvisioning from './components/BackupProvisioning';
import DemoteControllerModal from './components/DemoteControllerModal';
import ControllerTransitionModal from './components/ControllerTransitionModal';


const API_BASE = typeof window !== "undefined" && window.location.pathname.startsWith("/ad")
  ? "/ad/api"
  : (typeof window !== "undefined" && window.location.pathname.startsWith("/dns") ? "/dns/api" : "/api");

const customFetch = (url, opts = {}) => {
  const finalUrl = (typeof url === "string" && url.startsWith("/api"))
    ? (API_BASE + url.slice(4))
    : url;
  const headers = { ...(opts.headers || {}) };
  if (typeof window !== "undefined") {
    const params = new URLSearchParams(window.location.search);
    const qToken = params.get("token");
    if (qToken) {
      localStorage.setItem("astral_token", qToken);
      window.history.replaceState({}, document.title, window.location.pathname);
    }
    const token = localStorage.getItem("astral_token");
    if (token && !headers["Authorization"]) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return fetch(finalUrl, {
    ...opts,
    headers,
    credentials: opts.credentials || 'include',
  });
};

export default function App() {
  return <><ConfirmationDialog /><Application /></>;
}

function Application() {
  const [lang, setLang] = useState(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("astral_lang");
      if (saved && ["pt", "en", "es", "fr"].includes(saved)) return saved;
    }
    return "pt";
  });

  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("astral_lang", lang);
    }
  }, [lang]);
  const t = translations[lang] || translations.pt;
  const [activeTab, setActiveTab] = useState('dashboard');
  const [status, setStatus] = useState(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [showWizard, setShowWizard] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const [showDonations, setShowDonations] = useState(false);
  const [operator, setOperator] = useState(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [authProvider, setAuthProvider] = useState('ad');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [authError, setAuthError] = useState(null);

  const checkAuth = async () => {
    try {
      setAuthChecking(true);
      const res = await customFetch('/api/auth/me');
      if (res.ok) {
        const body = await res.json();
        if (body.success && body.data) {
          setOperator(body.data);
        } else {
          setOperator(null);
          try {
            const pRes = await customFetch('/api/auth/providers');
            if (pRes.ok) {
              const pData = await pRes.json();
              if (pData?.data?.recommended) setAuthProvider(pData.data.recommended);
            }
          } catch (_) {}
        }
      } else {
        setOperator(null);
        try {
          const pRes = await customFetch('/api/auth/providers');
          if (pRes.ok) {
            const pData = await pRes.json();
            if (pData?.data?.recommended) setAuthProvider(pData.data.recommended);
          }
        } catch (_) {}
      }
    } catch (err) {
      console.warn("Auth check failed:", err);
      setOperator(null);
      try {
        const pRes = await customFetch('/api/auth/providers');
        if (pRes.ok) {
          const pData = await pRes.json();
          if (pData?.data?.recommended) setAuthProvider(pData.data.recommended);
        }
      } catch (_) {}
    } finally {
      setAuthChecking(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    if (!authUsername.trim() || !authPassword) {
      setAuthError((t.usernameLabel || "Usuário") + " / " + (t.passwordLabel || "Senha"));
      return;
    }
    setAuthSubmitting(true);
    setAuthError(null);
    try {
      const res = await customFetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: authProvider,
          username: authUsername.trim(),
          password: authPassword,
        }),
      });
      const body = await res.json();
      if (res.ok && body.success && body.data) {
        if (body.data.token) {
          localStorage.setItem('astral_token', body.data.token);
        }
        setOperator(body.data.operator);
        showToast(t.loginSuccess || "Autenticado com sucesso!", 'success');
      } else {
        const msg = body.message || t.loginFailed || "Falha na autenticação";
        setAuthError(msg);
        showToast(msg, 'error');
      }
    } catch (err) {
      setAuthError(err.message || 'Erro de rede');
      showToast('Erro de rede', 'error');
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLogout = async () => {
    try {
      await customFetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {}
    localStorage.removeItem('astral_token');
    setOperator(null);
    showToast(t.logout || "Sessão encerrada", 'success');
  };

  const fetchStatus = async () => {
    try {
      setLoadingStatus(true);
      const res = await customFetch('/api/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch status:', err);
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    if (operator) {
      fetchStatus();
      const interval = setInterval(fetchStatus, 30000);
      return () => clearInterval(interval);
    }
  }, [operator]);

  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center font-sans">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-sm text-slate-400 font-mono">Astral AD & Hybrid DNS &middot; {t.signingIn || 'Carregando...'}</p>
        </div>
      </div>
    );
  }

  if (!operator) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between font-sans relative overflow-hidden">
        {toast && (
          <div className={`fixed bottom-5 right-5 z-50 px-5 py-3 rounded-lg shadow-xl border flex items-center gap-3 transition-all ${
            toast.type === 'error' ? 'bg-rose-950 border-rose-700 text-rose-200' : 'bg-emerald-950 border-emerald-700 text-emerald-200'
          }`}>
            {toast.type === 'error' ? <AlertTriangle className="w-5 h-5 text-rose-400" /> : <CheckCircle className="w-5 h-5 text-emerald-400" />}
            <span className="text-sm font-medium">{toast.message}</span>
          </div>
        )}

        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="w-full px-6 py-4 flex items-center justify-between z-10 border-b border-slate-900 bg-slate-950/70 backdrop-blur">
          <div className="flex items-center gap-3">
            <div className="bg-indigo-600/20 border border-indigo-500/40 p-2 rounded-xl text-indigo-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <span className="font-bold text-sm bg-gradient-to-r from-indigo-400 to-sky-300 bg-clip-text text-transparent">
                Astral AD & Hybrid DNS
              </span>
              <span className="hidden sm:inline-block ml-2 text-xs text-slate-500 font-mono">v1.4.0</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowDonations(true)}
              className="flex items-center gap-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition cursor-pointer"
              title={t.donate || "Apoiar / Doações"}
            >
              <Heart className="w-3.5 h-3.5 fill-rose-500 text-rose-500" />
              <span className="hidden sm:inline">{t.donate || "Apoiar"}</span>
            </button>
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs">
              <Globe className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
              <select
                value={lang}
                onChange={(e) => setLang(e.target.value)}
                className="bg-transparent text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer pr-2"
                aria-label={t.selectLanguage || "Selecionar Idioma"}
              >
              <option value="pt" className="bg-slate-900 text-slate-100">🇧🇷 Português (Brasil)</option>
              <option value="en" className="bg-slate-900 text-slate-100">🇺🇸 English (US)</option>
              <option value="es" className="bg-slate-900 text-slate-100">🇪🇸 Español (España)</option>
              <option value="fr" className="bg-slate-900 text-slate-100">🇫🇷 Français (France)</option>
            </select>
          </div>
          </div>
        </div>

        <div className="flex-1 flex items-center justify-center p-4 z-10">
          <div className="w-full max-w-md bg-slate-900/95 border border-slate-800 rounded-2xl shadow-2xl p-6 sm:p-8 backdrop-blur">
            <div className="text-center mb-6">
              <div className="inline-flex p-3 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 mb-3">
                <Lock className="w-7 h-7" />
              </div>
              <h2 className="text-xl font-bold text-slate-100 tracking-wide">{t.loginTitle || "Acesso Unificado Astral"}</h2>
              <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">{t.loginSubtitle || "Autenticação centralizada para infraestrutura e serviços Astral"}</p>
            </div>

            <div className="grid grid-cols-3 gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800/80 mb-5">
              <button
                type="button"
                onClick={() => { setAuthProvider('ad'); setAuthError(null); }}
                className={`flex flex-col items-center py-2 px-1 rounded-lg text-[11px] font-semibold transition cursor-pointer ${
                  authProvider === 'ad'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Shield className="w-4 h-4 mb-1" />
                <span className="truncate w-full text-center">Samba AD / SSO</span>
              </button>
              <button
                type="button"
                onClick={() => { setAuthProvider('linux'); setAuthError(null); }}
                className={`flex flex-col items-center py-2 px-1 rounded-lg text-[11px] font-semibold transition cursor-pointer ${
                  authProvider === 'linux'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-4 h-4 mb-1" />
                <span className="truncate w-full text-center">Linux Sudo</span>
              </button>
              <button
                type="button"
                onClick={() => { setAuthProvider('postgres'); setAuthError(null); }}
                className={`flex flex-col items-center py-2 px-1 rounded-lg text-[11px] font-semibold transition cursor-pointer ${
                  authProvider === 'postgres'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Database className="w-4 h-4 mb-1" />
                <span className="truncate w-full text-center">PostgreSQL</span>
              </button>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 mb-5 text-[11px] text-slate-400 leading-relaxed">
              {authProvider === 'ad' && (t.providerAdDesc || "Acesso via credenciais do domínio Samba AD ou token SSO emitido pelo auth-service.")}
              {authProvider === 'linux' && (t.providerLinuxDesc || "Acesso de administrador de sistema operacional com privilégios sudo (wheel/sudo) ou root.")}
              {authProvider === 'postgres' && (t.providerPostgresDesc || "Acesso via banco de dados para qualquer superusuário PostgreSQL (rolsuper = true).")}
            </div>

            {authError && (
              <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800/60 text-rose-200 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{authError}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">{t.usernameLabel || "Usuário"}</label>
                <div className="relative">
                  <User className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    placeholder={
                      authProvider === 'ad' ? "Administrator" :
                      authProvider === 'linux' ? "euripedes / root" : "postgres"
                    }
                    className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 transition focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">{t.passwordLabel || "Senha"}</label>
                <div className="relative">
                  <Key className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="password"
                    required
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 transition focus:outline-none"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={authSubmitting}
                className="w-full mt-2 py-2.5 px-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
              >
                {authSubmitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>{t.signingIn || "Autenticando..."}</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>{t.signInButton || "Entrar no Sistema"}</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        <div className="w-full text-center py-3 text-[11px] text-slate-500 border-t border-slate-900 bg-slate-950/40">
          {t.unifiedAuthNotice || "Política Unificada de Acesso: Samba AD / OAuth2, Linux Sudo, PostgreSQL Superuser ou Auth-Service SSO."}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Toast Notification */}
      {toast && (
        <div className={`fixed bottom-5 right-5 z-50 px-5 py-3 rounded-lg shadow-xl border flex items-center gap-3 transition-all ${
          toast.type === 'error' ? 'bg-rose-950 border-rose-700 text-rose-200' : 'bg-emerald-950 border-emerald-700 text-emerald-200'
        }`}>
          {toast.type === 'error' ? <AlertTriangle className="w-5 h-5 text-rose-400" /> : <CheckCircle className="w-5 h-5 text-emerald-400" />}
          <span className="text-sm font-medium">{toast.message}</span>
        </div>
      )}

      {/* Top Header */}
      <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-4">
          <div className="bg-indigo-600/20 border border-indigo-500/40 p-2 rounded-xl text-indigo-400 shadow-inner">
            <Server className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-bold tracking-wide bg-gradient-to-r from-indigo-400 via-sky-300 to-indigo-200 bg-clip-text text-transparent">
                {t.appTitle}
              </h1>
              {status && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-950 border border-indigo-700 text-indigo-300 font-mono font-medium">
                  {status.realm || 'AD 2016'}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">{t.appSubtitle}</p>
          </div>
        </div>

        {/* Status Indicators & Language Switcher */}
        <div className="flex items-center gap-3">
          {/* Overall Health Badge */}
          {status && (
            <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono font-semibold ${
              status.overall_health === 'operational'
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                : status.overall_health === 'degraded'
                ? 'bg-amber-950/80 text-amber-300 border-amber-700/60'
                : 'bg-rose-950/80 text-rose-300 border-rose-700/60'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                status.overall_health === 'operational' ? 'bg-emerald-400 animate-pulse' :
                status.overall_health === 'degraded' ? 'bg-amber-400' : 'bg-rose-400'
              }`} />
              <span className="capitalize">{status.overall_health === 'operational' ? t.healthOperational : status.overall_health === 'degraded' ? t.healthDegraded : t.healthUnavailable}</span>
            </div>
          )}
          {/* Status Pills */}
          <div className="hidden lg:flex items-center gap-2 bg-slate-950/80 border border-slate-800 px-3 py-1.5 rounded-lg text-xs">
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${status?.samba_active ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-slate-300 font-medium">{t.sambaDc}</span>
            </div>
            <span className="text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${status?.named_active ? 'bg-sky-400' : 'bg-amber-500'}`} />
              <span className="text-slate-300 font-medium">{t.bindHybrid}</span>
            </div>
            <span className="text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${status?.chrony_active ? 'bg-indigo-400' : 'bg-slate-500'}`} />
              <span className="text-slate-300 font-medium">{t.chronyNtp}</span>
            </div>
          </div>

          {/* Wizard Action Button */}
          <button 
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition shadow-sm border border-indigo-400/30"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>{t.wizard}</span>
          </button>

          {/* Operator Badge with Logout */}
          {operator && (
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 px-2.5 py-1 rounded-lg text-xs shadow-inner">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-400 hidden md:inline">{t.authenticatedAs || 'Operador:'}</span>
              <span className="font-semibold text-indigo-300 font-mono">{operator.username}</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold bg-indigo-950 text-indigo-400 border border-indigo-800/60">
                {operator.provider}
              </span>
              <button
                onClick={handleLogout}
                title={t.logout || 'Sair'}
                className="ml-1 text-slate-400 hover:text-rose-400 transition cursor-pointer p-0.5"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={() => setShowDonations(true)}
            className="flex items-center gap-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition cursor-pointer shadow-inner"
            title={t.donate || "Apoiar / Doações"}
          >
            <Heart className="w-3.5 h-3.5 fill-rose-500 text-rose-500" />
            <span className="hidden sm:inline">{t.donate || "Apoiar"}</span>
          </button>

          {/* Language Selector Dropdown (Caixa de Seleção) */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-700/80 hover:border-indigo-500/60 transition rounded-lg px-2.5 py-1.5 text-xs shadow-inner">
            <Globe className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
            <select
              value={lang}
              onChange={(e) => setLang(e.target.value)}
              className="bg-transparent text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer pr-2"
              aria-label={t.selectLanguage || "Selecionar Idioma"}
            >
              <option value="pt" className="bg-slate-900 text-slate-100 font-medium">🇧🇷 Português (Brasil)</option>
              <option value="en" className="bg-slate-900 text-slate-100 font-medium">🇺🇸 English (US)</option>
              <option value="es" className="bg-slate-900 text-slate-100 font-medium">🇪🇸 Español (España)</option>
              <option value="fr" className="bg-slate-900 text-slate-100 font-medium">🇫🇷 Français (France)</option>
            </select>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <div className="flex-1 flex flex-col md:flex-row">
        {/* Navigation Sidebar */}
        <aside className="w-full md:w-64 bg-slate-900/60 border-r border-slate-800/80 p-3 shrink-0 flex flex-row md:flex-col gap-1 overflow-x-auto">
          <NavItem active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} icon={<Activity className="w-4 h-4" />} label={t.dashboard} />
          <NavItem active={activeTab === 'users'} onClick={() => setActiveTab('users')} icon={<Users className="w-4 h-4" />} label={t.users} badge={status?.users_count} />
          <NavItem active={activeTab === 'groups'} onClick={() => setActiveTab('groups')} icon={<Shield className="w-4 h-4" />} label={t.groups} badge={status?.groups_count} />
          <NavItem active={activeTab === 'computers'} onClick={() => setActiveTab('computers')} icon={<Server className="w-4 h-4" />} label={t.computers} badge={status?.computers_count} />
          <NavItem active={activeTab === 'ou'} onClick={() => setActiveTab('ou')} icon={<FolderTree className="w-4 h-4 text-sky-400" />} label={t.ous || "Unidades (OU)"} />
          <NavItem active={activeTab === 'gpo'} onClick={() => setActiveTab('gpo')} icon={<Sliders className="w-4 h-4 text-amber-400" />} label={t.gpos || "Políticas (GPO)"} />
          <NavItem active={activeTab === 'dns'} onClick={() => setActiveTab('dns')} icon={<Globe className="w-4 h-4" />} label={t.dns} badge={status?.zones_count} />
          <NavItem active={activeTab === 'bind'} onClick={() => setActiveTab('bind')} icon={<Network className="w-4 h-4" />} label={t.bind} />
          <NavItem active={activeTab === 'health'} onClick={() => setActiveTab('health')} icon={<Layers className="w-4 h-4" />} label={t.health} />
          <NavItem active={activeTab === 'diagnostics'} onClick={() => setActiveTab('diagnostics')} icon={<Activity className="w-4 h-4 text-emerald-400" />} label={t.diagnostics} />
          <NavItem active={activeTab === 'forensics'} onClick={() => setActiveTab('forensics')} icon={<Shield className="w-4 h-4 text-cyan-400" />} label={t.forensics || 'Forense AD'} />
          <NavItem active={activeTab === 'audit'} onClick={() => setActiveTab('audit')} icon={<Terminal className="w-4 h-4 text-indigo-400" />} label={t.audit} />
          <NavItem active={activeTab === 'backups'} onClick={() => setActiveTab('backups')} icon={<HardDrive className="w-4 h-4" />} label={t.backups} />
          <NavItem active={activeTab === 'terminal'} onClick={() => setActiveTab('terminal')} icon={<Terminal className="w-4 h-4 text-emerald-400" />} label={t.terminal || "Terminal"} />
        </aside>

        {/* Tab Content */}
        <main className="flex-1 p-5 lg:p-7 overflow-y-auto">
          {activeTab === 'dashboard' && <DashboardTab status={status} t={t} fetchStatus={fetchStatus} showToast={showToast} />}
          {activeTab === 'users' && <UsersTab t={t} showToast={showToast} />}
          {activeTab === 'groups' && <GroupsTab t={t} showToast={showToast} />}
          {activeTab === 'computers' && <ComputersTab t={t} showToast={showToast} />}
          {activeTab === 'ou' && <OUTab t={t} showToast={showToast} customFetch={customFetch} />}
          {activeTab === 'gpo' && <GpoTab t={t} showToast={showToast} customFetch={customFetch} />}
          {activeTab === 'dns' && <DnsTab t={t} showToast={showToast} />}
          {activeTab === 'bind' && <BindTab t={t} showToast={showToast} />}
          {activeTab === 'health' && <HealthTab t={t} showToast={showToast} />}
          {activeTab === 'diagnostics' && <DiagnosticsTab t={t} showToast={showToast} />}
          {activeTab === 'forensics' && <ForensicsTab customFetch={customFetch} showToast={showToast} />}
          {activeTab === 'audit' && <AuditTab t={t} showToast={showToast} />}
          {activeTab === 'backups' && <BackupsTab t={t} showToast={showToast} />}
          {activeTab === 'terminal' && <TerminalTab t={t} operator={operator} showToast={showToast} customFetch={customFetch} />}
        </main>
      </div>

      {/* Provisioning Wizard Modal */}
      {showWizard && <WizardModal onClose={() => { setShowWizard(false); fetchStatus(); }} t={t} showToast={showToast} />}
      <DonationModal isOpen={showDonations} onClose={() => setShowDonations(false)} lang={lang} />
    </div>
  );
}

function NavItem({ active, onClick, icon, label, badge }) {
  return (
    <button 
      onClick={onClick}
      className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition ${
        active 
          ? 'bg-indigo-600 text-white font-semibold shadow-md shadow-indigo-950/50' 
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
      }`}
    >
      <div className="flex items-center gap-2.5">
        {icon}
        <span>{label}</span>
      </div>
      {badge !== undefined && (
        <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
          active ? 'bg-indigo-700/80 text-indigo-100' : 'bg-slate-800 text-slate-400'
        }`}>
          {badge}
        </span>
      )}
    </button>
  );
}

// ==============================================================================
// 1. DASHBOARD TAB
// ==============================================================================
function DashboardTab({ status, t, fetchStatus, showToast }) {
  const [testDomain, setTestDomain] = useState('google.com');
  const [benchmarking, setBenchmarking] = useState(false);
  const [benchResults, setBenchResults] = useState(null);
  const [checklistResults, setChecklistResults] = useState(null);
  const [checkingList, setCheckingList] = useState(false);

  const runChecklist = async () => {
    try {
      setCheckingList(true);
      const res = await customFetch('/api/checks');
      if (res.ok) {
        const json = await res.json();
        setChecklistResults(json.data || []);
        showToast(json.message);
      }
    } catch (e) {
      showToast('Falha ao executar checklist operacional', 'error');
    } finally {
      setCheckingList(false);
    }
  };

  const runBenchmark = async () => {
    if (!testDomain.trim()) return;
    try {
      setBenchmarking(true);
      const res = await customFetch('/api/bind/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: testDomain, record_type: 'A' })
      });
      if (res.ok) {
        const data = await res.json();
        setBenchResults(data);
      }
    } catch (e) {
      showToast('DNS test failed', 'error');
    } finally {
      setBenchmarking(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner Status */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <span className="text-xs px-2.5 py-1 rounded-md bg-emerald-950 border border-emerald-700 text-emerald-400 font-mono font-bold uppercase tracking-wider">
                Active Directory 2016
              </span>
              <span className="text-xs px-2.5 py-1 rounded-md bg-sky-950 border border-sky-700 text-sky-400 font-mono">
                FQDN: {status?.hostname || 'dc-erp.srvcloud.cloud'}
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {status?.realm || 'SRVCLOUD.CLOUD'}
            </h2>
            <p className="text-xs text-slate-400 max-w-xl">
              Controlador de domínio Samba 4 AD DC com níveis funcionais de Floresta e Domínio elevados para 2016. Encaminhamento recursivo isolado via BIND 9 na porta 5353.
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <MetricBox label={t.totalUsers} value={status?.users_count ?? '-'} icon={<Users className="w-4 h-4 text-indigo-400" />} />
            <MetricBox label={t.totalGroups} value={status?.groups_count ?? '-'} icon={<Shield className="w-4 h-4 text-emerald-400" />} />
            <MetricBox label={t.totalComputers} value={status?.computers_count ?? '-'} icon={<Server className="w-4 h-4 text-sky-400" />} />
            <MetricBox label={t.totalZones} value={status?.zones_count ?? '-'} icon={<Globe className="w-4 h-4 text-amber-400" />} />
          </div>
        </div>
      </div>

      {/* Domain Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Domain Parameters */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
              <Shield className="w-4 h-4" />
              <span>{t.domainLevel} / {t.forestLevel}</span>
            </div>
            <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
              {status?.functional_level_domain || '2016'}
            </span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.realm}:</span>
              <span className="font-mono text-slate-200 font-semibold">{status?.realm || '-'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.workgroup}:</span>
              <span className="font-mono text-slate-200 font-semibold">{status?.workgroup || '-'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.dnsForwarder}:</span>
              <span className="font-mono text-cyan-400">{status?.dns_forwarder || '127.0.0.1:5353'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">NetBIOS DC:</span>
              <span className="font-mono text-slate-200">{status?.netbios_name || 'DC-ERP'}</span>
            </div>
          </div>
        </div>

        {/* Hybrid BIND 9 Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-sky-400 font-semibold text-sm">
              <Network className="w-4 h-4" />
              <span>{t.bindHybrid}</span>
            </div>
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              status?.named_active ? 'bg-sky-950 text-sky-400 border-sky-800' : 'bg-rose-950 text-rose-400 border-rose-800'
            }`}>
              {status?.named_active ? t.active : t.inactive}
            </span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.listenResource}:</span>
              <span className="font-mono text-slate-200">127.0.0.1:5353</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Modo:</span>
              <span className="text-slate-300">{t.bindRecursiveOnly}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.bindConfigFile}:</span>
              <span className="font-mono text-slate-300">/etc/named.conf</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">{t.dnsCache}:</span>
              <span className="font-mono text-emerald-400">{t.dnsCacheEnabled}</span>
            </div>
          </div>
        </div>

        {/* Chrony NTP Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
              <Cpu className="w-4 h-4" />
              <span>{t.chronyNtp}</span>
            </div>
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              status?.chrony_active ? 'bg-blue-950 text-blue-400 border-blue-800' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              {status?.chrony_active ? t.synced : t.unsynced}
            </span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.refSource}:</span>
              <span className="font-mono text-slate-200">{status?.ntp?.reference_id || 'gps.nu.ntp.br'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Stratum:</span>
              <span className="font-mono text-slate-200">{status?.ntp?.stratum || 2}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{t.offset}:</span>
              <span className="font-mono text-emerald-400">{status?.ntp?.offset || '< 0.2ms'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">{t.kerberosSocket}:</span>
              <span className="font-mono text-slate-300">/var/lib/samba/ntp_signd</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick DNS Benchmark Tool */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>{t.quickDnsTestTitle}</span>
            </h3>
            <p className="text-xs text-slate-400">{t.quickDnsTestDesc}</p>
          </div>
          <div className="flex items-center gap-2">
            <input 
              type="text" 
              value={testDomain}
              onChange={(e) => setTestDomain(e.target.value)}
              placeholder="google.com"
              className="bg-slate-950 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-100 font-mono focus:border-indigo-500 focus:outline-none w-48"
            />
            <button 
              onClick={runBenchmark}
              disabled={benchmarking}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-1.5 rounded-lg flex items-center gap-1.5 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${benchmarking ? 'animate-spin' : ''}`} />
              <span>{benchmarking ? t.testing : t.runTest}</span>
            </button>
          </div>
        </div>

        {benchResults && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {benchResults.results.map((res, i) => (
              <div key={i} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{res.description}</span>
                  <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                    res.status === 'NOERROR' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400'
                  }`}>
                    {res.status}
                  </span>
                </div>
                <div className="flex items-baseline justify-between text-slate-400">
                  <span>{t.queryTime}:</span>
                  <span className="font-mono text-sm font-bold text-cyan-400">{res.query_time_ms} ms</span>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-300 max-h-24 overflow-y-auto">
                  {res.answer.length > 0 ? (
                    res.answer.map((ans, idx) => <div key={idx} className="truncate">{ans}</div>)
                  ) : (
                    <span className="text-slate-500 italic">Nenhum registro retornado</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {/* Operational Validation Checklist */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>{t.checklistTitle}</span>
            </h3>
            <p className="text-xs text-slate-400">{t.checklistDesc}</p>
          </div>
          <button 
            onClick={runChecklist}
            disabled={checkingList}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-1.5 transition shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${checkingList ? 'animate-spin' : ''}`} />
            <span>{checkingList ? t.runningChecklist : t.runChecklist}</span>
          </button>
        </div>

        {checklistResults && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
              <span>{t.batteryStatus}:</span>
              <span className="font-mono text-emerald-400 font-semibold">
                {checklistResults.filter(c => c.ok).length} / {checklistResults.length} {t.checkSuccess}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {checklistResults.map((check, idx) => (
                <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                      {check.ok ? (
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                      )}
                      <span>{check.name}</span>
                    </span>
                    <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                      check.ok ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {check.latency_ms} ms
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-400 bg-slate-900/80 p-2 rounded border border-slate-800/80 max-h-28 overflow-y-auto whitespace-pre-wrap">
                    <span className="text-slate-500">$ {check.command}</span>
                    <div className="text-slate-300 mt-1">{check.output}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function MetricBox({ label, value, icon }) {
  return (
    <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3 space-y-1">
      <div className="flex items-center justify-center gap-1.5 text-slate-400 text-[11px]">
        {icon}
        <span>{label}</span>
      </div>
      <div className="text-xl font-bold font-mono text-white">{value}</div>
    </div>
  );
}

// ==============================================================================
// 2. USERS TAB
// ==============================================================================
function UsersTab({ t, showToast }) {
  const [users, setUsers] = useState([]);
  const [dryRun, setDryRun] = useState(false);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(null);
  const [userGroupsModal, setUserGroupsModal] = useState(null);
  const [groupsList, setGroupsList] = useState([]);
  const [allDomainGroups, setAllDomainGroups] = useState([]);
  const [selectedAddGroup, setSelectedAddGroup] = useState('');
  const [groupLoading, setGroupLoading] = useState(false);
  const [selectedPropertiesUser, setSelectedPropertiesUser] = useState(null);
  const [userContextMenu, setUserContextMenu] = useState({ visible: false, x: 0, y: 0, user: null });

  // Form states
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [givenName, setGivenName] = useState('');
  const [surname, setSurname] = useState('');
  const [email, setEmail] = useState('');
  const [description, setDescription] = useState('');
  const [resetPwd, setResetPwd] = useState('');

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/users');
      if (res.ok) {
        const json = await res.json();
        setUsers(json.data || []);
      }
    } catch (e) {
      showToast('Failed to load users', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    const handleWindowClick = () => {
      setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
    };
    window.addEventListener('click', handleWindowClick);
    return () => window.removeEventListener('click', handleWindowClick);
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;

    try {
      const res = await customFetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: newUsername,
          password: newPassword,
          given_name: givenName || undefined,
          surname: surname || undefined,
          mail: email || undefined,
          description: description || undefined,
          dry_run: dryRun,
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowCreateModal(false);
        setNewUsername('');
        setNewPassword('');
        setGivenName('');
        setSurname('');
        setEmail('');
        setDescription('');
        fetchUsers();
      } else {
        showToast(data.message, 'error');
      }
    } catch (err) {
      showToast('Error creating user', 'error');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (!resetPwd.trim() || !showPasswordModal) return;

    try {
      const res = await customFetch(`/api/users/${showPasswordModal}/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: resetPwd })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowPasswordModal(null);
        setResetPwd('');
      } else {
        showToast(data.message, 'error');
      }
    } catch (err) {
      showToast('Error resetting password', 'error');
    }
  };

  const handleToggleEnable = async (user) => {
    const action = user.is_disabled ? 'enable' : 'disable';
    try {
      const res = await customFetch(`/api/users/${user.username}/${action}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchUsers();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast(`Error ${action}ing user`, 'error');
    }
  };

  const handleDeleteUser = async (username) => {
    if (!await confirmAction(`${t.confirmDeleteUser} '${username}'?`)) return;
    try {
      const res = await customFetch(`/api/users/${username}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchUsers();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error deleting user', 'error');
    }
  };

  const handleOpenUserGroups = async (username) => {
    setUserGroupsModal(username);
    setGroupsList([]);
    setSelectedAddGroup('');
    try {
      const res = await customFetch(`/api/users/${username}/groups`);
      if (res.ok) {
        const data = await res.json();
        setGroupsList(data.data || []);
      }
      const gRes = await customFetch('/api/groups');
      if (gRes.ok) {
        const gData = await gRes.json();
        setAllDomainGroups(gData.data || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddGroupToUser = async () => {
    if (!selectedAddGroup || !userGroupsModal) return;
    setGroupLoading(true);
    try {
      const res = await customFetch(`/api/users/${userGroupsModal}/groups/${selectedAddGroup}`, {
        method: 'POST'
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Grupo adicionado com sucesso!');
        const r = await customFetch(`/api/users/${userGroupsModal}/groups`);
        if (r.ok) {
          const d = await r.json();
          setGroupsList(d.data || []);
        }
        setSelectedAddGroup('');
      } else {
        showToast(data.message || 'Erro ao adicionar grupo', 'error');
      }
    } catch (e) {
      showToast('Falha na comunicação', 'error');
    } finally {
      setGroupLoading(false);
    }
  };

  const handleRemoveGroupFromUser = async (groupName) => {
    if (!groupName || !userGroupsModal) return;
    if (groupName.toLowerCase() === 'domain users') {
      showToast('Não é permitido remover o grupo primário Domain Users', 'warning');
      return;
    }
    setGroupLoading(true);
    try {
      const res = await customFetch(`/api/users/${userGroupsModal}/groups/${groupName}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Grupo removido com sucesso!');
        const r = await customFetch(`/api/users/${userGroupsModal}/groups`);
        if (r.ok) {
          const d = await r.json();
          setGroupsList(d.data || []);
        }
      } else {
        showToast(data.message || 'Erro ao remover grupo', 'error');
      }
    } catch (e) {
      showToast('Falha na comunicação', 'error');
    } finally {
      setGroupLoading(false);
    }
  };

  const filteredUsers = users.filter(u => u.username.toLowerCase().includes(search.toLowerCase()));

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
            placeholder={t.searchUsers}
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={fetchUsers} 
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
            <span>{t.addUser}</span>
          </button>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">{t.username}</th>
                <th className="py-3 px-4">{t.adminStatus}</th>
                <th className="py-3 px-4">{t.accountStatus}</th>
                <th className="py-3 px-4 text-right">{t.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredUsers.map((user) => (
                <tr 
                  key={user.username} 
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setUserContextMenu({ visible: true, x: e.clientX, y: e.clientY, user });
                  }}
                  className="hover:bg-slate-800/30 transition cursor-pointer select-none"
                >
                  <td 
                    onClick={() => setSelectedPropertiesUser(user.username)}
                    className="py-3 px-4 font-semibold text-slate-200 flex items-center gap-2 font-sans"
                  >
                    <div className="w-7 h-7 rounded-full bg-indigo-950 border border-indigo-700/60 flex items-center justify-center text-indigo-300 text-xs font-bold">
                      {user.username.charAt(0).toUpperCase()}
                    </div>
                    <span>{user.username}</span>
                  </td>
                  <td className="py-3 px-4 font-sans">
                    {user.is_admin ? (
                      <span className="px-2 py-0.5 rounded-full bg-amber-950/80 text-amber-300 border border-amber-800 text-[10px] font-bold">
                        {t.domainAdmin}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-xs">{t.standardUser}</span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-sans">
                    {user.is_disabled ? (
                      <span className="px-2 py-0.5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 text-[10px]">
                        {t.disabled}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                        {t.enabled}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right space-x-2 font-sans">
                    <button
                      type="button"
                      onClick={() => setSelectedPropertiesUser(user.username)}
                      className="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-slate-800 transition"
                      title="Ver Propriedades (Permissões, LDAP)"
                    >
                      <Info className="w-3.5 h-3.5" />
                    </button>
                    <button 
                      onClick={() => handleOpenUserGroups(user.username)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition"
                    >
                      {t.viewGroups}
                    </button>
                    <button 
                      onClick={() => setShowPasswordModal(user.username)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-indigo-900/60 text-indigo-300 text-[11px] transition"
                    >
                      {t.resetPassword}
                    </button>
                    <button 
                      onClick={() => handleToggleEnable(user)}
                      className={`px-2.5 py-1 rounded text-[11px] transition ${
                        user.is_disabled 
                          ? 'bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800' 
                          : 'bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {user.is_disabled ? t.enableUser : t.disableUser}
                    </button>
                    <button 
                      onClick={() => handleDeleteUser(user.username)}
                      className="p-1 rounded text-rose-400 hover:bg-rose-950/80 transition"
                      title={t.deleteUser}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Users className="w-4 h-4 text-indigo-400" />
              <span>{t.createUserTitle}</span>
            </h3>

            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.username} *</label>
                <input 
                  type="text" 
                  required 
                  value={newUsername} 
                  onChange={(e) => setNewUsername(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.newPassword} *</label>
                <input 
                  type="password" 
                  required 
                  value={newPassword} 
                  onChange={(e) => setNewPassword(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">{t.firstName}</label>
                  <input 
                    type="text" 
                    value={givenName} 
                    onChange={(e) => setGivenName(e.target.value)} 
                    className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">{t.lastName}</label>
                  <input 
                    type="text" 
                    value={surname} 
                    onChange={(e) => setSurname(e.target.value)} 
                    className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.email}</label>
                <input 
                  type="email" 
                  value={email} 
                  onChange={(e) => setEmail(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.description}</label>
                <input 
                  type="text" 
                  value={description} 
                  onChange={(e) => setDescription(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-sky-400">{t.dryRunOption}</div>
                  <div className="text-[11px] text-slate-400">{t.dryRunOptionHelp}</div>
                </div>
                <input 
                  type="checkbox" 
                  checked={dryRun} 
                  onChange={(e) => setDryRun(e.target.checked)} 
                  className="rounded border-slate-700 bg-slate-900 text-indigo-600 focus:ring-0 w-4 h-4 cursor-pointer"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {showPasswordModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              <span>{t.resetPassword}: {showPasswordModal}</span>
            </h3>

            <form onSubmit={handleResetPassword} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.newPassword}</label>
                <input 
                  type="password" 
                  required 
                  value={resetPwd} 
                  onChange={(e) => setResetPwd(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowPasswordModal(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* User Groups Modal - Gerenciamento e Alteração de Grupos */}
      {userGroupsModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Gerenciar Grupos de: <span className="text-indigo-400">{userGroupsModal}</span></span>
              </h3>
              <button onClick={() => setUserGroupsModal(null)} className="text-slate-400 hover:text-white">&times;</button>
            </div>

            {/* Adicionar a um novo grupo */}
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-2 text-xs">
              <label className="block text-slate-300 font-semibold">Adicionar ao Grupo do Domínio:</label>
              <div className="flex gap-2">
                <select
                  value={selectedAddGroup}
                  onChange={(e) => setSelectedAddGroup(e.target.value)}
                  disabled={groupLoading}
                  className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100 focus:border-indigo-500 focus:outline-none"
                >
                  <option value="">Selecione um grupo...</option>
                  {allDomainGroups
                    .filter(g => !groupsList.includes(g.groupname))
                    .map((g) => (
                      <option key={g.groupname} value={g.groupname}>
                        {g.groupname}
                      </option>
                    ))}
                </select>
                <button
                  type="button"
                  onClick={handleAddGroupToUser}
                  disabled={!selectedAddGroup || groupLoading}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded-lg transition flex items-center gap-1.5"
                >
                  {groupLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>Adicionar</span>
                </button>
              </div>
            </div>

            {/* Lista de Grupos Atuais */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">Grupos Atuais ({groupsList.length}):</span>
                {groupLoading && <span className="text-[11px] text-indigo-400 flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> Sincronizando...</span>}
              </div>

              <div className="max-h-60 overflow-y-auto space-y-1.5 text-xs font-mono pr-1">
                {groupsList.map((g, idx) => (
                  <div key={idx} className="bg-slate-950 border border-slate-800 px-3 py-2 rounded-lg text-slate-200 flex items-center justify-between hover:border-slate-700 transition">
                    <div className="flex items-center gap-2">
                      <Shield className={`w-3.5 h-3.5 shrink-0 ${
                        g === 'Domain Admins' || g === 'Enterprise Admins' || g === 'Administrators' ? 'text-amber-400' : 'text-indigo-400'
                      }`} />
                      <span className="font-semibold">{g}</span>
                      {g === 'Domain Users' && (
                        <span className="text-[10px] text-slate-500 font-sans italic">(Primário)</span>
                      )}
                    </div>
                    {g.toLowerCase() !== 'domain users' && (
                      <button
                        type="button"
                        onClick={() => handleRemoveGroupFromUser(g)}
                        disabled={groupLoading}
                        className="px-2 py-0.5 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[10px] transition font-sans flex items-center gap-1"
                        title={`Remover ${userGroupsModal} do grupo ${g}`}
                      >
                        <Trash2 className="w-2.5 h-2.5" />
                        <span>Remover</span>
                      </button>
                    )}
                  </div>
                ))}
                {groupsList.length === 0 && (
                  <div className="text-slate-500 text-center py-4 font-sans">{t.loadingGroups}</div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button 
                onClick={() => setUserGroupsModal(null)} 
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* User Context Menu */}
      {userContextMenu.visible && userContextMenu.user && (
        <div
          style={{ top: `${userContextMenu.y}px`, left: `${userContextMenu.x}px` }}
          className="fixed z-50 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl py-1.5 w-52 text-xs font-sans divide-y divide-slate-800"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 text-[10px] text-slate-400 font-mono font-bold truncate">
            {userContextMenu.user.username}
          </div>
          <div className="py-1">
            <button
              onClick={() => {
                setSelectedPropertiesUser(userContextMenu.user.username);
                setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-slate-800 flex items-center gap-2 text-slate-200 transition"
            >
              <Info className="w-3.5 h-3.5 text-sky-400" />
              <span>Propriedades (LDAP)</span>
            </button>
            <button
              onClick={() => {
                handleOpenUserGroups(userContextMenu.user.username);
                setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-slate-800 flex items-center gap-2 text-slate-200 transition"
            >
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span>Gerenciar Grupos</span>
            </button>
            <button
              onClick={() => {
                setShowPasswordModal(userContextMenu.user.username);
                setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-slate-800 flex items-center gap-2 text-slate-200 transition"
            >
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>Redefinir Senha</span>
            </button>
            <button
              onClick={() => {
                handleToggleEnable(userContextMenu.user);
                setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-slate-800 flex items-center gap-2 text-slate-200 transition"
            >
              <Activity className="w-3.5 h-3.5 text-indigo-400" />
              <span>{userContextMenu.user.is_disabled ? t.enableUser : t.disableUser}</span>
            </button>
            <button
              onClick={() => {
                handleDeleteUser(userContextMenu.user.username);
                setUserContextMenu({ visible: false, x: 0, y: 0, user: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-rose-950/80 text-rose-300 flex items-center gap-2 transition"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Excluir Usuário</span>
            </button>
          </div>
        </div>
      )}

      {/* User Properties Modal */}
      {selectedPropertiesUser && (
        <UserPropertiesModal
          username={selectedPropertiesUser}
          onClose={() => setSelectedPropertiesUser(null)}
          customFetch={customFetch}
          showToast={showToast}
        />
      )}
    </div>
  );
}

// ==============================================================================
// 3. GROUPS TAB
// ==============================================================================
function GroupsTab({ t, showToast }) {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [members, setMembers] = useState([]);
  const [newMemberUsername, setNewMemberUsername] = useState('');
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDesc, setNewGroupDesc] = useState('');

  const fetchGroups = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/groups');
      if (res.ok) {
        const json = await res.json();
        setGroups(json.data || []);
      }
    } catch (e) {
      showToast('Failed to load groups', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, []);

  const openGroupMembers = async (groupname) => {
    setSelectedGroup(groupname);
    setMembers([]);
    try {
      const res = await customFetch(`/api/groups/${encodeURIComponent(groupname)}/members`);
      if (res.ok) {
        const json = await res.json();
        setMembers(json.data || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddMember = async (e) => {
    e.preventDefault();
    if (!newMemberUsername.trim() || !selectedGroup) return;

    try {
      const res = await customFetch(`/api/groups/${encodeURIComponent(selectedGroup)}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newMemberUsername })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setNewMemberUsername('');
        openGroupMembers(selectedGroup);
      } else {
        showToast(data.message, 'error');
      }
    } catch (err) {
      showToast('Error adding member', 'error');
    }
  };

  const handleRemoveMember = async (username) => {
    if (!await confirmAction(`Remover ${username} do grupo ${selectedGroup}?`)) return;
    try {
      const res = await customFetch(`/api/groups/${encodeURIComponent(selectedGroup)}/members/${encodeURIComponent(username)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        openGroupMembers(selectedGroup);
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error removing member', 'error');
    }
  };

  const handleCreateGroup = async (e) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;

    try {
      const res = await customFetch('/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groupname: newGroupName, description: newGroupDesc || undefined })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowCreateModal(false);
        setNewGroupName('');
        setNewGroupDesc('');
        fetchGroups();
      } else {
        showToast(data.message, 'error');
      }
    } catch (err) {
      showToast('Error creating group', 'error');
    }
  };

  const handleDeleteGroup = async (groupname) => {
    if (!await confirmAction(`Excluir o grupo ${groupname}?`)) return;
    try {
      const res = await customFetch(`/api/groups/${encodeURIComponent(groupname)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchGroups();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error deleting group', 'error');
    }
  };

  const filteredGroups = groups.filter(g => g.name.toLowerCase().includes(search.toLowerCase()));

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
            placeholder={t.searchGroups}
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={fetchGroups} 
            className="p-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg text-slate-300 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button 
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md"
          >
            <Plus className="w-4 h-4" />
            <span>{t.addGroup}</span>
          </button>
        </div>
      </div>

      {/* Groups Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {filteredGroups.map((group) => (
          <div key={group.name} className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition shadow-sm space-y-3">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-950/70 border border-indigo-700/50 flex items-center justify-center text-indigo-400">
                  <Shield className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-100 font-mono">{group.name}</h4>
                  <span className="text-[10px] text-slate-400">Grupo de Segurança</span>
                </div>
              </div>
              <button 
                onClick={() => handleDeleteGroup(group.name)}
                className="text-slate-500 hover:text-rose-400 p-1 rounded transition"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
              <button 
                onClick={() => openGroupMembers(group.name)}
                className="text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1"
              >
                <span>{t.viewMembers}</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Group Members Drawer / Modal */}
      {selectedGroup && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white font-mono">{selectedGroup}</h3>
                <p className="text-xs text-slate-400">{t.membersTitle}</p>
              </div>
              <button onClick={() => setSelectedGroup(null)} className="text-slate-400 hover:text-white">&times;</button>
            </div>

            {/* Add Member Input */}
            <form onSubmit={handleAddMember} className="flex gap-2">
              <input 
                type="text" 
                value={newMemberUsername}
                onChange={(e) => setNewMemberUsername(e.target.value)}
                placeholder="Nome do usuário para adicionar..."
                className="flex-1 bg-slate-950 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
              />
              <button 
                type="submit" 
                className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition"
              >
                {t.addMember}
              </button>
            </form>

            {/* Member List */}
            <div className="max-h-60 overflow-y-auto space-y-1.5 text-xs font-mono">
              {members.map((m, idx) => (
                <div key={idx} className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-300">
                    <Users className="w-3 h-3 text-indigo-400" />
                    <span>{m}</span>
                  </div>
                  <button 
                    onClick={() => handleRemoveMember(m)}
                    className="text-rose-400 hover:text-rose-300 text-[11px]"
                  >
                    {t.removeMember}
                  </button>
                </div>
              ))}
              {members.length === 0 && (
                <div className="text-slate-500 text-center py-4 font-sans text-xs">Nenhum membro neste grupo.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create Group Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-indigo-400" />
              <span>{t.addGroup}</span>
            </h3>

            <form onSubmit={handleCreateGroup} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.groupName} *</label>
                <input 
                  type="text" 
                  required 
                  value={newGroupName} 
                  onChange={(e) => setNewGroupName(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.description}</label>
                <input 
                  type="text" 
                  value={newGroupDesc} 
                  onChange={(e) => setNewGroupDesc(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ==============================================================================
// 4. COMPUTERS TAB
// ==============================================================================
function ComputersTab({ t, showToast }) {
  const [transition, setTransition] = useState(null);
  const [demoteComputer, setDemoteComputer] = useState(null);
  const [computers, setComputers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [newComputerName, setNewComputerName] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedPropertiesComp, setSelectedPropertiesComp] = useState(null);
  const [contextMenu, setContextMenu] = useState({ visible: false, x: 0, y: 0, comp: null });

  const fetchComputers = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/computers');
      if (res.ok) {
        const json = await res.json();
        setComputers(json.data || []);
      }
    } catch (e) {
      showToast('Failed to load computers', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchComputers();
  }, []);

  useEffect(() => {
    const handleWindowClick = () => {
      setContextMenu({ visible: false, x: 0, y: 0, comp: null });
    };
    window.addEventListener('click', handleWindowClick);
    return () => window.removeEventListener('click', handleWindowClick);
  }, []);

  const handleContextMenu = (e, comp) => {
    e.preventDefault();
    setContextMenu({ visible: true, x: e.clientX, y: e.clientY, comp });
  };

  const handleCreateComputer = async (e) => {
    e.preventDefault();
    if (!newComputerName.trim()) return;

    try {
      const res = await customFetch('/api/computers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ computername: newComputerName })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowAddModal(false);
        setNewComputerName('');
        fetchComputers();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error creating computer account', 'error');
    }
  };

  const handleDeleteComputer = async (name) => {
    const computer = computers.find(c => c.name === name);
    const deadDc = !!computer?.is_dc;
    const warning = deadDc
      ? `Remover os metadados do DC desativado ${name}? Confirme que ele foi desligado permanentemente e não voltará ao domínio. Para DC ativo, execute samba-tool domain demote nele primeiro.`
      : `Excluir conta de computador ${name}?`;
    if (!await confirmAction(warning)) return;
    try {
      const res = await customFetch(`/api/computers/${encodeURIComponent(name)}?remove_dead_dc=${deadDc}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchComputers();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error deleting computer account', 'error');
    }
  };

  const filtered = computers.filter(c => c.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input 
            type="text" 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t.searchComputers}
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={fetchComputers} 
            className="p-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg text-slate-300 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button 
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md"
          >
            <Plus className="w-4 h-4" />
            <span>{t.addComputer}</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map((comp) => (
          <div 
            key={comp.name} 
            onContextMenu={(e) => handleContextMenu(e, comp)}
            className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 shadow-sm flex items-center justify-between transition cursor-pointer select-none"
          >
            <div 
              onClick={() => setSelectedPropertiesComp(comp.name)}
              className="flex items-center gap-3 flex-1"
            >
              <div className="w-9 h-9 rounded-lg bg-sky-950 border border-sky-800/60 flex items-center justify-center text-sky-400 shrink-0">
                <Server className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-1">
                  <span>{comp.name}</span>{comp.is_primary && <span className="text-amber-300"> · Primário protegido</span>}
                </h4>
                <span className={`text-[10px] px-2 py-0.5 rounded font-sans ${
                  comp.is_dc ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'text-slate-400'
                }`}>
                  {comp.is_rodc ? "RODC · Somente leitura" : comp.is_dc ? t.domainController : t.workstation}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap justify-end items-center gap-1 max-w-40">
              <button
                type="button"
                onClick={() => setSelectedPropertiesComp(comp.name)}
                className="p-1.5 text-slate-400 hover:text-sky-300 hover:bg-slate-800 rounded transition"
                title="Ver Propriedades (IP, MAC, Máscara, LDAP)"
              >
                <Info className="w-3.5 h-3.5" />
              </button>

              {comp.is_dc && !comp.is_primary && <button onClick={() => setTransition({ computer: comp, action: comp.is_rodc ? 'promote_writable' : 'promote_primary' })} className="text-[10px] text-cyan-300 px-2 py-1 rounded bg-cyan-950">{comp.is_rodc ? 'Tornar gravável' : 'Promover a principal'}</button>}
              {comp.is_dc && !comp.is_primary && <button onClick={() => setDemoteComputer(comp)} className="text-[10px] text-amber-300 px-2 py-1 rounded bg-amber-950">Despromover</button>}
              {!comp.is_local && !comp.is_primary && (
                <button 
                  onClick={() => handleDeleteComputer(comp.name)}
                  className="text-slate-500 hover:text-rose-400 p-1.5 rounded transition"
                  title={comp.is_dc ? "Remover DC desativado" : "Excluir Computador"}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Floating Context Menu */}
      {contextMenu.visible && contextMenu.comp && (
        <div
          style={{ top: `${contextMenu.y}px`, left: `${contextMenu.x}px` }}
          className="fixed z-50 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl py-1.5 w-48 text-xs font-sans divide-y divide-slate-800"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 text-[10px] text-slate-400 font-mono font-bold truncate">
            {contextMenu.comp.name}
          </div>
          <div className="py-1">
            <button
              onClick={() => {
                setSelectedPropertiesComp(contextMenu.comp.name);
                setContextMenu({ visible: false, x: 0, y: 0, comp: null });
              }}
              className="w-full px-3 py-1.5 text-left hover:bg-slate-800 flex items-center gap-2 text-slate-200 transition"
            >
              <Info className="w-3.5 h-3.5 text-sky-400" />
              <span>Propriedades</span>
            </button>
            {!contextMenu.comp.is_local && !contextMenu.comp.is_primary && (
              <button
                onClick={() => {
                  handleDeleteComputer(contextMenu.comp.name);
                  setContextMenu({ visible: false, x: 0, y: 0, comp: null });
                }}
                className="w-full px-3 py-1.5 text-left hover:bg-rose-950/80 text-rose-300 flex items-center gap-2 transition"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                <span>Excluir Computador</span>
              </button>
            )}
          </div>
        </div>
      )}

      {transition && <ControllerTransitionModal {...transition} customFetch={customFetch} showToast={showToast} onClose={() => setTransition(null)} onSuccess={fetchComputers} />}
      {demoteComputer && <DemoteControllerModal computer={demoteComputer} customFetch={customFetch} showToast={showToast} onClose={() => setDemoteComputer(null)} onSuccess={fetchComputers} />}
      {/* Computer Properties Modal */}
      {selectedPropertiesComp && (
        <ComputerPropertiesModal
          computerName={selectedPropertiesComp}
          onClose={() => setSelectedPropertiesComp(null)}
          customFetch={customFetch}
          showToast={showToast}
        />
      )}

      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-indigo-400" />
              <span>{t.addComputer}</span>
            </h3>

            <form onSubmit={handleCreateComputer} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.computerName} *</label>
                <input 
                  type="text" 
                  required 
                  value={newComputerName} 
                  onChange={(e) => setNewComputerName(e.target.value)} 
                  placeholder="EX: DESKTOP-FINANCEIRO"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none font-mono"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ==============================================================================
// 5. DNS MANAGEMENT TAB (WITH AUTO REVERSE PTR CREATION)
// ==============================================================================
function DnsTab({ t, showToast }) {
  const [zones, setZones] = useState([]);
  const [selectedZone, setSelectedZone] = useState('');
  const [records, setRecords] = useState([]);
  const [loadingZones, setLoadingZones] = useState(true);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [search, setSearch] = useState('');

  // Modals
  const [showAddZoneModal, setShowAddZoneModal] = useState(false);
  const [newZoneName, setNewZoneName] = useState('');
  const [showAddRecordModal, setShowAddRecordModal] = useState(false);

  // New record form
  const [recName, setRecName] = useState('@');
  const [recType, setRecType] = useState('A');
  const [recData, setRecData] = useState('');
  const [autoPtr, setAutoPtr] = useState(true);

  const fetchZones = async () => {
    try {
      setLoadingZones(true);
      const res = await customFetch('/api/dns/zones');
      if (res.ok) {
        const json = await res.json();
        const zlist = json.data || [];
        setZones(zlist);
        if (zlist.length > 0 && !selectedZone) {
          setSelectedZone(zlist[0].name);
        }
      }
    } catch (e) {
      showToast('Failed to load DNS zones', 'error');
    } finally {
      setLoadingZones(false);
    }
  };

  const fetchRecords = async (zoneName) => {
    if (!zoneName) return;
    try {
      setLoadingRecords(true);
      const res = await customFetch(`/api/dns/zones/${zoneName}/records`);
      if (res.ok) {
        const json = await res.json();
        setRecords(json.data || []);
      }
    } catch (e) {
      showToast(`Failed to load records for ${zoneName}`, 'error');
    } finally {
      setLoadingRecords(false);
    }
  };

  useEffect(() => {
    fetchZones();
  }, []);

  useEffect(() => {
    if (selectedZone) {
      fetchRecords(selectedZone);
    }
  }, [selectedZone]);

  const handleCreateZone = async (e) => {
    e.preventDefault();
    if (!newZoneName.trim()) return;

    try {
      const res = await customFetch('/api/dns/zones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ zone_name: newZoneName })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowAddZoneModal(false);
        setNewZoneName('');
        fetchZones();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error creating zone', 'error');
    }
  };

  const handleDeleteZone = async (zoneName) => {
    if (!await confirmAction(`Excluir permanentemente a zona DNS ${zoneName}?`)) return;
    try {
      const res = await customFetch(`/api/dns/zones/${zoneName}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchZones();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error deleting zone', 'error');
    }
  };

  const handleAddRecord = async (e) => {
    e.preventDefault();
    if (!recData.trim() || !selectedZone) return;

    try {
      const res = await customFetch(`/api/dns/zones/${selectedZone}/records`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: recName,
          record_type: recType,
          data: recData,
          create_ptr: recType === 'A' ? autoPtr : false,
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setShowAddRecordModal(false);
        setRecName('@');
        setRecData('');
        fetchRecords(selectedZone);
        fetchZones(); // in case a new reverse zone was created
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error adding DNS record', 'error');
    }
  };

  const handleDeleteRecord = async (rec) => {
    if (!await confirmAction(`Excluir o registro ${rec.record_type}: ${rec.name} -> ${rec.data}?`)) return;
    try {
      const res = await customFetch(`/api/dns/zones/${selectedZone}/records`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: rec.name,
          record_type: rec.record_type,
          data: rec.data,
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchRecords(selectedZone);
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error deleting record', 'error');
    }
  };

  const filteredRecords = records.filter(r => 
    r.name.toLowerCase().includes(search.toLowerCase()) || 
    r.data.toLowerCase().includes(search.toLowerCase()) ||
    r.record_type.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      {/* Zone Switcher Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-white">{t.zones}</h3>
          </div>
          <button 
            onClick={() => setShowAddZoneModal(true)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t.addZone}</span>
          </button>
        </div>

        {/* Zone Pills */}
        <div className="flex flex-wrap gap-2 pt-1">
          {zones.map((z) => (
            <button
              key={z.name}
              onClick={() => setSelectedZone(z.name)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition border ${
                selectedZone === z.name 
                  ? 'bg-indigo-600 border-indigo-500 text-white font-bold shadow' 
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <span>{z.name}</span>
              {z.is_reverse && (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800/60 font-sans">
                  PTR
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Selected Zone Records */}
      {selectedZone && (
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input 
                type="text" 
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filtrar registros por nome, tipo ou IP..."
                className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none font-mono"
              />
            </div>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => fetchRecords(selectedZone)} 
                className="p-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg text-slate-300 transition"
              >
                <RefreshCw className={`w-4 h-4 ${loadingRecords ? 'animate-spin' : ''}`} />
              </button>
              <button 
                onClick={() => setShowAddRecordModal(true)}
                className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md"
              >
                <Plus className="w-4 h-4" />
                <span>{t.addRecord}</span>
              </button>
            </div>
          </div>

          {/* Records Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-3 px-4">{t.recordName}</th>
                    <th className="py-3 px-4">{t.recordType}</th>
                    <th className="py-3 px-4">{t.recordData}</th>
                    <th className="py-3 px-4">{t.ttl}</th>
                    <th className="py-3 px-4 text-right">{t.actions}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredRecords.map((rec, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition">
                      <td className="py-2.5 px-4 font-bold text-slate-200">{rec.name}</td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          rec.record_type === 'A' ? 'bg-sky-950 text-sky-400 border border-sky-800' :
                          rec.record_type === 'PTR' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                          rec.record_type === 'CNAME' ? 'bg-indigo-950 text-indigo-400 border border-indigo-800' :
                          rec.record_type === 'SRV' ? 'bg-purple-950 text-purple-400 border border-purple-800' :
                          'bg-slate-800 text-slate-300'
                        }`}>
                          {rec.record_type}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300 break-all">{rec.data}</td>
                      <td className="py-2.5 px-4 text-slate-500">{rec.ttl}s</td>
                      <td className="py-2.5 px-4 text-right">
                        {!['SOA', 'NS'].includes(rec.record_type) && (
                          <button 
                            onClick={() => handleDeleteRecord(rec)}
                            className="text-slate-500 hover:text-rose-400 p-1 rounded transition"
                            title={t.deleteRecord}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Add Record Modal */}
      {showAddRecordModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              <span>{t.addRecord} na Zona {selectedZone}</span>
            </h3>

            <form onSubmit={handleAddRecord} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.recordName} *</label>
                <input 
                  type="text" 
                  required 
                  value={recName} 
                  onChange={(e) => setRecName(e.target.value)} 
                  placeholder="@ para raiz ou subdomínio (ex: dc-erp, fileserver)"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.recordType}</label>
                <select 
                  value={recType} 
                  onChange={(e) => setRecType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none font-mono"
                >
                  <option value="A">A (Endereço IPv4)</option>
                  <option value="PTR">PTR (Ponteiro Reverso)</option>
                  <option value="CNAME">CNAME (Alias)</option>
                  <option value="TXT">TXT (Texto)</option>
                  <option value="SRV">SRV (Serviço)</option>
                  <option value="MX">MX (Mail Server)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.recordData} *</label>
                <input 
                  type="text" 
                  required 
                  value={recData} 
                  onChange={(e) => setRecData(e.target.value)} 
                  placeholder={recType === 'A' ? '192.168.2.50' : 'destino.srvcloud.cloud'}
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none font-mono"
                />
              </div>

              {/* Auto PTR Toggle */}
              {recType === 'A' && (
                <div className="bg-slate-950 border border-indigo-900/60 rounded-lg p-3 space-y-1">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-200 font-medium">
                    <input 
                      type="checkbox" 
                      checked={autoPtr} 
                      onChange={(e) => setAutoPtr(e.target.checked)} 
                      className="rounded bg-slate-800 border-slate-700 text-indigo-600 focus:ring-0"
                    />
                    <span>{t.autoPtrLabel}</span>
                  </label>
                  <p className="text-[11px] text-slate-400 pl-6 leading-relaxed">
                    {t.autoPtrHelp}
                  </p>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowAddRecordModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Zone Modal */}
      {showAddZoneModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-indigo-400" />
              <span>{t.addZone}</span>
            </h3>

            <form onSubmit={handleCreateZone} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Nome da Zona *</label>
                <input 
                  type="text" 
                  required 
                  value={newZoneName} 
                  onChange={(e) => setNewZoneName(e.target.value)} 
                  placeholder="ex: filial.empresa.lan ou 10.168.192.in-addr.arpa"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none font-mono"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button 
                  type="button" 
                  onClick={() => setShowAddZoneModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  {t.cancel}
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
                >
                  {t.save}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ==============================================================================
// 6. HYBRID BIND 9 MANAGEMENT TAB
// ==============================================================================
function BindTab({ t, showToast }) {
  const [bindStatus, setBindStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [forwarders, setForwarders] = useState([]);
  const [newFwd, setNewFwd] = useState('');
  const [saving, setSaving] = useState(false);
  const [logs, setLogs] = useState([]);

  const fetchBind = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/bind/status');
      if (res.ok) {
        const data = await res.json();
        setBindStatus(data);
        setForwarders(data.forwarders || []);
      }
      const lres = await customFetch('/api/bind/logs');
      if (lres.ok) {
        const ldata = await lres.json();
        setLogs(ldata.data || []);
      }
    } catch (e) {
      showToast('Failed to load BIND status', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBind();
  }, []);

  const handleAddForwarder = () => {
    if (!newFwd.trim()) return;
    if (!forwarders.includes(newFwd.trim())) {
      setForwarders([...forwarders, newFwd.trim()]);
      setNewFwd('');
    }
  };

  const handleRemoveForwarder = (ip) => {
    setForwarders(forwarders.filter(f => f !== ip));
  };

  const handleSaveForwarders = async (dryRun = false) => {
    if (!dryRun && !await confirmAction('Aplicar o BIND recursivo em loopback? A configuração será validada, com cópia anterior e rollback se o serviço ou os testes DNS falharem.')) return;
    try {
      setSaving(true);
      const res = await customFetch('/api/bind/forwarders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ forwarders, dry_run: dryRun })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchBind();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error saving forwarders', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleServiceAction = async (action) => {
    try {
      const res = await customFetch(`/api/bind/service/${action}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchBind();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast(`Error executing ${action}`, 'error');
    }
  };

  return (
    <div className="space-y-6">
      {bindStatus && <div className="text-xs space-y-2 p-4 bg-slate-900 border border-slate-700 rounded-xl">
        <p>Serviço: {bindStatus.service_name} · Sintaxe: {bindStatus.syntax_valid ? 'válida' : 'verificar'} · Listener TCP/UDP: {bindStatus.listening_on_5353 ? 'ativo' : 'incompleto'} · Loopback: {bindStatus.loopback_only ? 'restrito' : 'verificar'}</p>
        {(bindStatus.warnings || []).map((warning, index) => <p key={index} className="text-amber-300">{warning}</p>)}
      </div>}
      {/* Hybrid DNS Architectural Overview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-sky-400 font-bold text-sm">
          <Network className="w-5 h-5" />
          <span>{t.bindArchitecture}</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
          {t.bindArchDesc}
        </p>

        {/* Visual Architecture Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 text-center text-xs font-mono">
          <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Clientes da Rede</span>
            <div className="text-slate-200 font-bold">Clientes AD</div>
            <span className="text-[10px] text-indigo-400">DNS do domínio</span>
          </div>
          <div className="bg-indigo-950/60 border border-indigo-700/60 p-3 rounded-lg space-y-1">
            <span className="text-[10px] text-indigo-300 uppercase">Samba 4 AD DC</span>
            <div className="text-white font-bold">Porta 53 (Padrão)</div>
            <span className="text-[10px] text-emerald-400">Autoritativo AD</span>
          </div>
          <div className="bg-sky-950/60 border border-sky-700/60 p-3 rounded-lg space-y-1">
            <span className="text-[10px] text-sky-300 uppercase">BIND 9 Híbrido</span>
            <div className="text-white font-bold">127.0.0.1:5353</div>
            <span className="text-[10px] text-sky-400">Recursivo Seguro</span>
          </div>
          <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Internet / Upstream</span>
            <div className="text-slate-200 font-bold">{bindStatus?.forwarders?.join(" / ") || "Configure upstreams"}</div>
            <span className="text-[10px] text-cyan-400">Resolução Global</span>
          </div>
        </div>
      </div>

      {/* Forwarders Management Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white">{t.bindForwardersTitle}</h3>
            <p className="text-xs text-slate-400">{t.bindForwardersDesc}</p>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => handleServiceAction('reload')} 
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
            >
              {t.reloadService}
            </button>
            <button 
              onClick={() => handleServiceAction('restart')} 
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
            >
              {t.restartService}
            </button>
          </div>
        </div>

        {/* Forwarders List & Add */}
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {forwarders.map((ip) => (
              <div key={ip} className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono text-xs">
                <Globe className="w-3.5 h-3.5 text-sky-400" />
                <span className="text-slate-200">{ip}</span>
                <button 
                  onClick={() => handleRemoveForwarder(ip)}
                  className="text-slate-500 hover:text-rose-400 transition"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>

          <div className="flex gap-2 max-w-sm">
            <input 
              type="text" 
              value={newFwd}
              onChange={(e) => setNewFwd(e.target.value)}
              placeholder="IPv4 ou IPv6 do DNS upstream"
              className="flex-1 bg-slate-950 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-100 font-mono focus:border-indigo-500 focus:outline-none"
            />
            <button 
              onClick={handleAddForwarder}
              className="bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition"
            >
              {t.addForwarder}
            </button>
          </div>

          <div className="pt-2 flex gap-3">
            <button onClick={() => handleSaveForwarders(true)} disabled={saving} className="px-4 py-2 rounded bg-slate-800 text-slate-200 text-xs">Validar plano</button>
            <button 
              onClick={() => handleSaveForwarders(false)}
              disabled={saving}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${saving ? 'animate-spin' : ''}`} />
              <span>{t.applyAndReload}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Query Logs Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>{t.bindLogs}</span>
        </h3>
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-64 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1">
          {logs.map((log, idx) => (
            <div key={idx} className="hover:bg-slate-900/60 px-1 py-0.5 rounded transition">
              {log}
            </div>
          ))}
          {logs.length === 0 && (
            <div className="text-slate-500 italic py-2">Nenhum log recente capturado.</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ==============================================================================
// 7. HEALTH, REPLICATION & SYSVOL TAB
// ==============================================================================
function HealthTab({ t, showToast }) {
  const [drs, setDrs] = useState(null);
  const [loadingDrs, setLoadingDrs] = useState(false);
  const [dbChecking, setDbChecking] = useState(false);
  const [dbOutput, setDbOutput] = useState(null);
  const [fixDb, setFixDb] = useState(false);
  const [sysvolResult, setSysvolResult] = useState(null);
  const [checkingSysvol, setCheckingSysvol] = useState(false);
  const [psScript, setPsScript] = useState('');

  const fetchDrs = async () => {
    try {
      setLoadingDrs(true);
      const res = await customFetch('/api/health/drs');
      if (res.ok) {
        const json = await res.json();
        setDrs(json.data);
      }
    } catch (e) {
      showToast('Failed to check DRS status', 'error');
    } finally {
      setLoadingDrs(false);
    }
  };

  const fetchScript = async () => {
    try {
      const res = await customFetch('/api/health/sysvol-script');
      if (res.ok) {
        const json = await res.json();
        setPsScript(json.data || '');
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchDrs();
    fetchScript();
  }, []);

  const handleDbCheck = async () => {
    try {
      setDbChecking(true);
      const res = await customFetch('/api/health/dbcheck', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fix: fixDb })
      });
      const json = await res.json();
      setDbOutput(json.data);
      showToast(json.message, json.success ? 'success' : 'error');
    } catch (e) {
      showToast('Error during dbcheck', 'error');
    } finally {
      setDbChecking(false);
    }
  };

  const handleSysvolCheck = async () => {
    try {
      setCheckingSysvol(true);
      const res = await customFetch('/api/health/sysvolcheck', { method: 'POST' });
      const json = await res.json();
      setSysvolResult(json.data);
      showToast(json.message, json.success ? 'success' : 'error');
    } catch (e) {
      showToast('Error checking sysvol', 'error');
    } finally {
      setCheckingSysvol(false);
    }
  };

  const handleSysvolReset = async () => {
    if (!await confirmAction('Deseja realmente restaurar as permissões e ACLs padrão do SYSVOL?')) return;
    try {
      setCheckingSysvol(true);
      const res = await customFetch('/api/health/sysvolreset', { method: 'POST' });
      const json = await res.json();
      setSysvolResult(json.data);
      showToast(json.message, json.success ? 'success' : 'error');
    } catch (e) {
      showToast('Error resetting sysvol', 'error');
    } finally {
      setCheckingSysvol(false);
    }
  };

  const copyScriptToClipboard = () => {
    navigator.clipboard.writeText(psScript);
    showToast(t.scriptCopied);
  };

  return (
    <div className="space-y-6">
      {/* DRS Replication Status Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-white">{t.drsTitle}</h3>
          </div>
          <button 
            onClick={fetchDrs} 
            className="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingDrs ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {drs && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
              <span className="text-slate-400 font-sans">{t.dsaGuid}</span>
              <div className="font-mono text-[11px] text-slate-200 truncate">{drs.dsa_guid || 'N/A'}</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
              <span className="text-slate-400 font-sans">{t.invocationId}</span>
              <div className="font-mono text-[11px] text-slate-200 truncate">{drs.invocation_id || 'N/A'}</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
              <span className="text-slate-400 font-sans">{t.inboundNeighbors}</span>
              <div className="font-mono text-sm font-bold text-emerald-400">{drs.inbound_neighbors_count}</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1">
              <span className="text-slate-400 font-sans">{t.outboundNeighbors}</span>
              <div className="font-mono text-sm font-bold text-sky-400">{drs.outbound_neighbors_count}</div>
            </div>
          </div>
        )}
      </div>

      {/* Database Integrity Check (dbcheck) Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>{t.dbcheckTitle}</span>
            </h3>
            <p className="text-xs text-slate-400">{t.dbcheckDesc}</p>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
              <input 
                type="checkbox" 
                checked={fixDb} 
                onChange={(e) => setFixDb(e.target.checked)} 
                className="rounded bg-slate-950 border-slate-700 text-indigo-600"
              />
              <span>{t.fixErrors}</span>
            </label>
            <button 
              onClick={handleDbCheck}
              disabled={dbChecking}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg transition flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${dbChecking ? 'animate-spin' : ''}`} />
              <span>{dbChecking ? 'Verificando...' : t.runDbcheck}</span>
            </button>
          </div>
        </div>

        {dbOutput && (
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] max-h-48 overflow-y-auto text-slate-300">
            <pre className="whitespace-pre-wrap">{dbOutput.stdout || dbOutput.stderr}</pre>
          </div>
        )}
      </div>

      {/* SYSVOL ACLs Integrity Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-amber-400" />
              <span>{t.sysvolTitle}</span>
            </h3>
            <p className="text-xs text-slate-400">Verifique e restaure os descritores de segurança (NTACLs) das políticas de grupo (GPOs) no sysvol.</p>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={handleSysvolCheck}
              disabled={checkingSysvol}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
            >
              {t.runSysvolCheck}
            </button>
            <button 
              onClick={handleSysvolReset}
              disabled={checkingSysvol}
              className="px-3 py-1.5 bg-amber-950 hover:bg-amber-900 border border-amber-800 text-amber-300 text-xs font-semibold rounded-lg transition"
            >
              {t.runSysvolReset}
            </button>
          </div>
        </div>

        {sysvolResult && (
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-300">
            <pre className="whitespace-pre-wrap">{sysvolResult.stdout || sysvolResult.stderr || 'Verificação concluída com sucesso!'}</pre>
          </div>
        )}
      </div>

      {/* Windows DC2 SYSVOL Replication Script */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white">{t.powershellScriptTitle}</h3>
            <p className="text-xs text-slate-400">{t.powershellScriptDesc}</p>
          </div>
          <button 
            onClick={copyScriptToClipboard}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-indigo-950 hover:text-indigo-300 text-slate-300 text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-700 transition"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>{t.copyScript}</span>
          </button>
        </div>

        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-56 overflow-y-auto font-mono text-[11px] text-slate-300">
          <pre className="whitespace-pre-wrap">{psScript}</pre>
        </div>
      </div>
    </div>
  );
}

// ==============================================================================
// 8. BACKUPS TAB
// ==============================================================================
function BackupsTab({ t, showToast }) {
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [restoreModalFile, setRestoreModalFile] = useState(null);

  const fetchBackups = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/backups');
      if (res.ok) {
        const json = await res.json();
        setBackups(json.data || []);
      }
    } catch (e) {
      showToast('Failed to load backups', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBackups();
  }, []);

  const handleCreateBackup = async () => {
    try {
      setCreating(true);
      const res = await customFetch('/api/backups', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchBackups();
      } else {
        showToast(data.message, 'error');
      }
    } catch (e) {
      showToast('Error creating backup', 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteBackup = async (filename) => {
    if (!await confirmAction(`Deseja realmente excluir o backup ${filename}?`)) return;
    try {
      const res = await customFetch(`/api/backups/${encodeURIComponent(filename)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Backup excluído');
        fetchBackups();
      } else {
        showToast(data.message || 'Erro ao excluir backup', 'error');
      }
    } catch (e) {
      showToast('Falha na comunicação ao excluir backup', 'error');
    }
  };

  return (
    <div className="space-y-4">
      <BackupProvisioning customFetch={customFetch} showToast={showToast} />
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-indigo-400" />
            <span>{t.backupsTitle}</span>
          </h3>
          <p className="text-xs text-slate-400">{t.backupsDesc}</p>
        </div>
        <button 
          onClick={handleCreateBackup}
          disabled={creating}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md flex items-center gap-1.5 shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${creating ? 'animate-spin' : ''}`} />
          <span>{creating ? t.creatingBackup : t.createBackup}</span>
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">{t.filename}</th>
                <th className="py-3 px-4">{t.size}</th>
                <th className="py-3 px-4">{t.createdAt}</th>
                <th className="py-3 px-4 text-right">{t.actions || 'Ações'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {backups.map((b) => (
                <tr key={b.filename} className="hover:bg-slate-800/30 transition">
                  <td className="py-3 px-4 text-slate-200 font-semibold">{b.filename}</td>
                  <td className="py-3 px-4 text-emerald-400">{b.size_human}</td>
                  <td className="py-3 px-4 text-slate-400">{b.created_at}</td>
                  <td className="py-3 px-4 text-right space-x-2 font-sans">
                    <button
                      onClick={() => setRestoreModalFile(b.filename)}
                      className="px-2.5 py-1 rounded bg-amber-950/80 hover:bg-amber-900 border border-amber-800 text-amber-300 text-[11px] font-sans inline-flex items-center gap-1.5 transition shadow-sm"
                      title="Restaurar Backup do Samba AD preservando rede"
                    >
                      <RotateCcw className="w-3 h-3" />
                      <span>{t.restoreBackup || "Restaurar"}</span>
                    </button>
                    <button
                      onClick={() => handleDeleteBackup(b.filename)}
                      className="p-1.5 rounded text-rose-400 hover:bg-rose-950/80 transition inline-flex items-center"
                      title="Excluir Backup"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {backups.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                    {t.noBackupsNotice}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Restore Backup Modal */}
      {restoreModalFile && (
        <RestoreBackupModal
          filename={restoreModalFile}
          onClose={() => setRestoreModalFile(null)}
          onSuccess={() => {
            setRestoreModalFile(null);
            fetchBackups();
          }}
          customFetch={customFetch}
          showToast={showToast}
        />
      )}
    </div>
  );
}


// ==============================================================================
// 9. DIAGNOSTICS & FIREWALL AUDIT TAB
// ==============================================================================
function DiagnosticsTab({ t, showToast }) {
  const [diagData, setDiagData] = useState(null);
  const [loadingDiag, setLoadingDiag] = useState(false);
  const [firewallData, setFirewallData] = useState(null);
  const [loadingFw, setLoadingFw] = useState(false);
  const [openingFw, setOpeningFw] = useState(false);
  const [dryRunFw, setDryRunFw] = useState(false);
  const [migrationData, setMigrationData] = useState(null);
  const [loadingMigration, setLoadingMigration] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [reconciling, setReconciling] = useState(false);

  const fetchMigrationStatus = async () => {
    try {
      setLoadingMigration(true);
      const res = await customFetch('/api/firewall/migration/status');
      if (res.ok) {
        const json = await res.json();
        setMigrationData(json.data);
      }
    } catch (e) {
      console.warn("Falha ao carregar status de migração:", e);
    } finally {
      setLoadingMigration(false);
    }
  };

  const handleAutoReconcile = async () => {
    try {
      setReconciling(true);
      const res = await customFetch('/api/firewall/auto-reconcile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dry_run: dryRunFw })
      });
      const json = await res.json();
      showToast(json.message || "Auto-reconciliação concluída", json.success ? 'success' : 'error');
      fetchFirewall();
      fetchMigrationStatus();
    } catch (e) {
      showToast('Erro ao reconciliar portas do firewall', 'error');
    } finally {
      setReconciling(false);
    }
  };

  const handleMigrateFirewall = async () => {
    if (!await confirmAction("Deseja iniciar a migração automática para iptables? O sistema gerará backup criptográfico SHA-256 de todas as regras atuais em /var/backups/astral-ad-dns/firewall e testará antes de aplicar.")) {
      return;
    }
    try {
      setMigrating(true);
      const res = await customFetch('/api/firewall/migration/migrate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dry_run: false })
      });
      const json = await res.json();
      showToast(json.message || "Migração para iptables concluída com sucesso!", json.success ? 'success' : 'error');
      fetchFirewall();
      fetchMigrationStatus();
    } catch (e) {
      showToast('Erro durante a migração para iptables', 'error');
    } finally {
      setMigrating(false);
    }
  };

  const fetchDiagnostics = async () => {
    try {
      setLoadingDiag(true);
      const res = await customFetch('/api/diagnostics');
      if (res.ok) {
        const json = await res.json();
        setDiagData(json.data);
      }
    } catch (e) {
      showToast('Falha ao carregar diagnósticos de infraestrutura', 'error');
    } finally {
      setLoadingDiag(false);
    }
  };

  const fetchFirewall = async () => {
    try {
      setLoadingFw(true);
      const res = await customFetch('/api/firewall');
      if (res.ok) {
        const json = await res.json();
        setFirewallData(json.data);
      }
    } catch (e) {
      showToast('Falha ao carregar status do firewall', 'error');
    } finally {
      setLoadingFw(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
    fetchFirewall();
    fetchMigrationStatus();
  }, []);

  const handleOpenPorts = async () => {
    try {
      setOpeningFw(true);
      const res = await customFetch('/api/firewall/open', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dry_run: dryRunFw })
      });
      const json = await res.json();
      showToast(json.message, json.success ? 'success' : 'error');
      fetchFirewall();
    } catch (e) {
      showToast('Erro ao abrir portas do firewall', 'error');
    } finally {
      setOpeningFw(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Activity className="w-5 h-5 text-emerald-400" />
            <h2 className="text-xl font-bold text-white tracking-tight">{t.diagnosticsTitle}</h2>
          </div>
          <p className="text-xs text-slate-400 max-w-xl">{t.diagnosticsDesc}</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => { fetchDiagnostics(); fetchFirewall(); }}
            disabled={loadingDiag || loadingFw}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg transition shadow-md"
          >
            <RefreshCw className={`w-4 h-4 ${loadingDiag || loadingFw ? 'animate-spin' : ''}`} />
            <span>{loadingDiag ? t.refreshingDiagnostics : t.refreshDiagnostics}</span>
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400">
            <CheckCircle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-semibold">{t.healthOperational}</div>
            <div className="text-xl font-bold text-white font-mono">{diagData?.summary?.operational ?? 0}</div>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-amber-950 border border-amber-800 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-semibold">{t.healthDegraded}</div>
            <div className="text-xl font-bold text-white font-mono">{diagData?.summary?.degraded ?? 0}</div>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-rose-950 border border-rose-800 flex items-center justify-center text-rose-400">
            <XCircle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-semibold">{t.healthUnavailable}</div>
            <div className="text-xl font-bold text-white font-mono">{diagData?.summary?.unavailable ?? 0}</div>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 uppercase font-semibold">{t.firewallAdCounter}</div>
            <div className="text-xl font-bold text-white font-mono">
              {firewallData ? `${firewallData.open_count}/${firewallData.total_ports}` : '-'}
            </div>
          </div>
        </div>
      </div>

      {/* Diagnostics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {diagData?.checks?.map((check) => (
          <div key={check.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-indigo-400">
                  {check.category}
                </span>
                <h4 className="text-sm font-semibold text-white mt-1.5">{check.name}</h4>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                  {check.latency_ms} ms
                </span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                  check.status === 'operational'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : check.status === 'degraded'
                    ? 'bg-amber-950 text-amber-400 border border-amber-800'
                    : check.status === 'unavailable'
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}>
                  {check.status === 'operational' ? t.healthOperational :
                   check.status === 'degraded' ? t.healthDegraded :
                   check.status === 'unavailable' ? t.healthUnavailable : t.healthUnknown}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              {check.message}
            </p>

            {check.possible_cause && (
              <div className="bg-rose-950/40 border border-rose-800/60 rounded-lg p-2.5 text-xs text-rose-300">
                <span className="font-bold">{t.possibleCause}: </span>
                {check.possible_cause}
              </div>
            )}

            {check.recommended_action && (
              <div className="bg-sky-950/40 border border-sky-800/60 rounded-lg p-2.5 text-xs text-sky-300">
                <span className="font-bold">{t.recommendedAction}: </span>
                {check.recommended_action}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Firewall Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-sky-400" />
              <span>{t.firewallTitle}</span>
            </h3>
            <p className="text-xs text-slate-400">{t.firewallDesc}</p>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-sky-300">
              <input 
                type="checkbox" 
                checked={dryRunFw} 
                onChange={(e) => setDryRunFw(e.target.checked)} 
                className="rounded border-slate-700 bg-slate-950 text-indigo-600 focus:ring-0"
              />
              <span>{t.dryRunOption}</span>
            </label>
            <button
              onClick={handleAutoReconcile}
              disabled={reconciling || openingFw}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 transition shadow-sm cursor-pointer"
              title="Auto-reconciliar e sincronizar portas de serviços ativos no iptables"
            >
              <RefreshCw className={reconciling ? "w-3.5 h-3.5 animate-spin" : "w-3.5 h-3.5"} />
              <span>{reconciling ? (t.reconciling || 'Reconciliando...') : (t.autoReconcilePorts || 'Reconciliar Portas Ativas')}</span>
            </button>
            <button
              onClick={handleOpenPorts}
              disabled={openingFw || reconciling}
              className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 transition shadow-sm cursor-pointer"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>{openingFw ? t.openingPorts : t.openMissingPorts}</span>
            </button>
          </div>
        </div>

        {/* Migration Section */}
        <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">{t.firewallMigrationTitle || "Migração e Compatibilidade de Firewall"}</h4>
                <p className="text-[11px] text-slate-400">{t.firewallMigrationDesc || "Unificação de regras para iptables com backup criptográfico SHA-256 e rollback automático."}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {migrationData?.iptables_active ? (
                <span className="px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> {t.iptablesActive || "iptables Ativo"}
                </span>
              ) : (
                <span className="px-2.5 py-1 rounded-full bg-amber-950 text-amber-400 border border-amber-800 text-[10px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> {t.iptablesInactive || "iptables Inativo"}
                </span>
              )}
              {migrationData?.migration_needed && (
                <button
                  onClick={handleMigrateFirewall}
                  disabled={migrating}
                  className="bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-bold px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition shadow cursor-pointer"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>{migrating ? "Migrando..." : (t.migrateToIptables || "Migrar para iptables")}</span>
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">{t.currentManager || "Gerenciador Ativo:"}</span>
              <span className="font-semibold text-white uppercase font-mono">{migrationData?.current_active_manager || "Detectando..."}</span>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Status da Migração:</span>
              <span className={migrationData?.migration_needed ? "font-semibold text-amber-400" : "font-semibold text-emerald-400"}>
                {migrationData?.migration_needed ? (t.migrationRequired || "Migração Recomendada") : (t.migrationNotRequired || "iptables Operacional")}
              </span>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Backups Versionados (/var/backups):</span>
              <span className="font-mono text-cyan-400 font-semibold">{migrationData?.available_backups?.length || 0} snapshot(s)</span>
            </div>
          </div>
        </div>

        {/* Safety Warning */}
        <div className="bg-indigo-950/40 border border-indigo-800/60 rounded-lg p-3 text-xs text-indigo-300 flex items-start gap-2.5">
          <Shield className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
          <span>
            <strong>{t.strictSafetyNotice}:</strong> {t.strictSafetyNoticeDesc}
          </span>
        </div>

        {/* Ports Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-2.5 px-4">{t.portProtocol}</th>
                <th className="py-2.5 px-4">{t.portNumber}</th>
                <th className="py-2.5 px-4">{t.portService}</th>
                <th className="py-2.5 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {firewallData?.ports?.map((p, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition">
                  <td className="py-2.5 px-4 font-bold text-slate-300 uppercase">{p.proto}</td>
                  <td className="py-2.5 px-4 text-cyan-400 font-bold">{p.port}</td>
                  <td className="py-2.5 px-4 text-slate-300 font-sans">{p.label}</td>
                  <td className="py-2.5 px-4 text-right">
                    {p.is_open ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                        {t.portOpen}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 text-[10px] font-bold">
                        {t.portClosed}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ==============================================================================
// 10. OPERATIONAL AUDIT TRAIL TAB
// ==============================================================================
function AuditTab({ t, showToast }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filterType, setFilterType] = useState('all');
  const [search, setSearch] = useState('');
  const [clearing, setClearing] = useState(false);

  const fetchAudit = async () => {
    try {
      setLoading(true);
      const res = await customFetch('/api/audit');
      if (res.ok) {
        const json = await res.json();
        setEvents(json.data || []);
      }
    } catch (e) {
      showToast('Falha ao carregar trilha de auditoria', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, []);

  const handleClear = async () => {
    if (!await confirmAction(t.confirmClearAudit)) return;
    try {
      setClearing(true);
      const res = await customFetch('/api/audit/clear', { method: 'POST' });
      const json = await res.json();
      showToast(json.message);
      fetchAudit();
    } catch (e) {
      showToast('Erro ao limpar histórico', 'error');
    } finally {
      setClearing(false);
    }
  };

  const filteredEvents = events.filter((e) => {
    if (filterType === 'dry_run' && !e.dry_run) return false;
    if (filterType === 'real' && e.dry_run) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchAction = e.action?.toLowerCase().includes(q);
      const matchTarget = e.target?.toLowerCase().includes(q);
      const matchOp = e.operator?.toLowerCase().includes(q);
      const matchDetails = e.details?.toLowerCase().includes(q);
      const matchId = e.id?.toLowerCase().includes(q);
      if (!matchAction && !matchTarget && !matchOp && !matchDetails && !matchId) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Terminal className="w-5 h-5 text-indigo-400" />
            <h2 className="text-xl font-bold text-white tracking-tight">{t.auditTitle}</h2>
          </div>
          <p className="text-xs text-slate-400 max-w-xl">{t.auditDesc}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAudit}
            disabled={loading}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold px-4 py-2 rounded-lg transition border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{t.refreshAudit}</span>
          </button>
          <button
            onClick={handleClear}
            disabled={clearing || events.length === 0}
            className="flex items-center gap-1.5 bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 disabled:opacity-50 text-xs font-semibold px-4 py-2 rounded-lg transition border border-rose-800/60"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>{clearing ? t.clearingAudit : t.clearAudit}</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs font-medium">
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-1.5 rounded-md transition ${filterType === 'all' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'}`}
          >
            {t.filterAll} ({events.length})
          </button>
          <button
            onClick={() => setFilterType('dry_run')}
            className={`px-3 py-1.5 rounded-md transition ${filterType === 'dry_run' ? 'bg-sky-600 text-white font-semibold' : 'text-slate-400 hover:text-white'}`}
          >
            {t.filterDryRun} ({events.filter(e => e.dry_run).length})
          </button>
          <button
            onClick={() => setFilterType('real')}
            className={`px-3 py-1.5 rounded-md transition ${filterType === 'real' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-white'}`}
          >
            {t.filterReal} ({events.filter(e => !e.dry_run).length})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t.filterSearchPlaceholder}
            className="w-full bg-slate-900 border border-slate-800 text-xs pl-9 pr-4 py-2 rounded-lg text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">{t.eventTimestamp}</th>
                <th className="py-3 px-4">{t.eventOperator}</th>
                <th className="py-3 px-4">{t.eventAction}</th>
                <th className="py-3 px-4">{t.eventTarget}</th>
                <th className="py-3 px-4">{t.eventType}</th>
                <th className="py-3 px-4">{t.eventStatus}</th>
                <th className="py-3 px-4">{t.eventDetails}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {filteredEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-slate-800/30 transition">
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                    {new Date(evt.timestamp).toLocaleString()}
                    <div className="text-[10px] text-slate-600 font-mono">{evt.id}</div>
                  </td>
                  <td className="py-3 px-4 font-sans font-semibold text-slate-300">
                    <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                      {evt.operator || 'admin'}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-bold text-indigo-400">
                    {evt.action}
                  </td>
                  <td className="py-3 px-4 text-cyan-300 font-sans font-medium">
                    {evt.target}
                  </td>
                  <td className="py-3 px-4 font-sans">
                    {evt.dry_run ? (
                      <span className="px-2 py-0.5 rounded-full bg-sky-950 text-sky-400 border border-sky-800 text-[10px] font-bold">
                        {t.dryRunBadge}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                        {t.realBadge}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-sans">
                    {evt.success ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>OK</span>
                      </span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>FALHA</span>
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-300 font-sans max-w-xs truncate" title={evt.details}>
                    {evt.details}
                  </td>
                </tr>
              ))}
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    {t.noAuditEvents}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ==============================================================================
// 11. ACTIVE DIRECTORY PROVISIONING WIZARD MODAL
// ==============================================================================
function WizardModal({ onClose, t, showToast }) {
  const [step, setStep] = useState(1);
  const [preflight, setPreflight] = useState(null);
  const [loadingPreflight, setLoadingPreflight] = useState(true);
  const [mode, setMode] = useState('join_dc'); // 'new' | 'join_dc' | 'join_rodc' | 'join_member'
  const dnsBackend = 'SAMBA_INTERNAL';

  // Form
  const [realm, setRealm] = useState('SRVCLOUD.CLOUD');
  const [workgroup, setWorkgroup] = useState('SRVCLOUD');
  const [adminPassword, setAdminPassword] = useState('');
  const [setupBind, setSetupBind] = useState(false);
  const [targetDcIp, setTargetDcIp] = useState('');
  const [targetAdmin, setTargetAdmin] = useState('administrator');
  const [dcNetbiosName, setDcNetbiosName] = useState('DC2');
  const [rejoin, setRejoin] = useState(false);
  const [configurationOnly, setConfigurationOnly] = useState(false);
  const [upstreamText, setUpstreamText] = useState('8.8.8.8, 1.1.1.1');
  const [globalCatalog, setGlobalCatalog] = useState(true);
  const [lastResult, setLastResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [cleanExisting, setCleanExisting] = useState(false);
  const [setupStepCa, setSetupStepCa] = useState(false);
  const [initializeCa, setInitializeCa] = useState(true);
  const [caUrl, setCaUrl] = useState('');
  const [caPort, setCaPort] = useState(8443);
  const [caCertHours, setCaCertHours] = useState(8760);
  const [caFingerprint, setCaFingerprint] = useState('');
  const [certPassword, setCertPassword] = useState('');
  const [tlsPaths, setTlsPaths] = useState({cert: '', key: '', ca: ''});
  const [networkInterface, setNetworkInterface] = useState('');

  // Execution
  const [executing, setExecuting] = useState(false);
  const [completedSteps, setCompletedSteps] = useState([]);
  const [errorMsg, setErrorMsg] = useState(null);

  // DNS Verification & Sync
  const [dnsCheck, setDnsCheck] = useState(null);
  const [syncingDns, setSyncingDns] = useState(false);

  const checkAdDns = async () => {
    try {
      const res = await customFetch('/api/provision/verify-ad-dns?' + new URLSearchParams({ realm, target_dc_ip: targetDcIp.trim() }));
      if (res.ok) {
        const data = await res.json();
        setDnsCheck(data);
        if (data.hostname) {
          setDcNetbiosName(current => !current || current === 'DC2' ? data.hostname.toUpperCase() : current);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSyncDns = async () => {
    setSyncingDns(true);
    try {
      const res = await customFetch('/api/provision/sync-ad-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          realm,
          target_dc_ip: targetDcIp,
          admin_username: targetAdmin,
          admin_password: adminPassword,
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'DNS do AD sincronizado com sucesso!');
        await checkAdDns();
      } else {
        showToast(data.message || 'Erro na sincronização DNS', 'error');
      }
    } catch (e) {
      showToast('Falha na comunicação com o servidor', 'error');
    } finally {
      setSyncingDns(false);
    }
  };

  useEffect(() => {
    async function loadPreflight() {
      try {
        setLoadingPreflight(true);
        const res = await customFetch('/api/provision/preflight');
        if (res.ok) {
          const data = await res.json();
          setPreflight(data);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoadingPreflight(false);
      }
    }
    loadPreflight();
    checkAdDns();
  }, []);

  useEffect(() => {
    const timer = setTimeout(checkAdDns, 350);
    return () => clearTimeout(timer);
  }, [realm, targetDcIp]);

  const followProvisionJob = async (id) => {
    for (;;) {
      const response = await customFetch('/api/provision/jobs/' + encodeURIComponent(id));
      const envelope = await response.json();
      if (!response.ok) throw new Error(envelope.message || 'Nao foi possivel consultar a operacao. Verifique os backups antes de repetir.');
      const job = envelope.data;
      if (job.state === 'finished') {
        localStorage.removeItem('astral.provision.job');
        return job.result;
      }
      if (job.state === 'interrupted') throw new Error('Servico reiniciado durante a operacao. Consulte o historico/backup antes de retomar.');
      setCompletedSteps([...(job.steps_completed || []), 'Etapa atual: ' + (job.phase || 'preparacao')]);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  };

  useEffect(() => {
    customFetch('/api/provision/history').then(response => response.json()).then(data => setHistory(Array.isArray(data.data) ? data.data : [])).catch(() => {});
    const id = localStorage.getItem('astral.provision.job');
    if (id) {
      setExecuting(true); setStep(4);
      followProvisionJob(id).then(result => {
        setLastResult(result); setCompletedSteps(result.steps_completed || []);
        if (!result.success) setErrorMsg(result.message || result.error);
      }).catch(error => setErrorMsg(error.message)).finally(() => setExecuting(false));
    }
  }, []);

  const handleStartProvision = async () => {
    const pending = localStorage.getItem('astral.provision.job');
    if (pending) {
      setStep(4); setExecuting(true);
      try {
        const result = await followProvisionJob(pending);
        setLastResult(result); setCompletedSteps(result.steps_completed || []);
        setErrorMsg(result.success ? null : result.message || result.error);
      } catch (error) { setErrorMsg(error.message); }
      finally { setExecuting(false); }
      return;
    }
    if (mode !== 'new' && !configurationOnly && !targetDcIp.trim()) {
      showToast('Informe o IP do DC parceiro para consultar o AD na porta 53.', 'error');
      return;
    }
    if (setupStepCa && mode !== 'join_member' && !certPassword) { showToast('Informe a senha da PKI.', 'error'); return; }
    if (!adminPassword) {
      showToast('Informe a senha do administrador do dominio.', 'error');
      return;
    }
    const upstreams = upstreamText.split(/[\s,;]+/).filter(Boolean);
    if (!upstreams.length) { showToast('Informe pelo menos um forwarder DNS.', 'error'); return; }
    if (rejoin && !configurationOnly && !await confirmAction('Executar backup automatico, despromover quando necessario, limpar o estado local e ingressar no papel selecionado? O primario/FSMO sera protegido.')) return;
    setLastResult(null);
    setExecuting(true);
    setCompletedSteps([]);
    setErrorMsg(null);
    setStep(4);

    try {
      const endpoint = mode === 'new' ? '/api/provision/new-dc' : '/api/provision/join-dc';
      const domainRole = mode === 'join_rodc' ? 'RODC' : mode === 'join_member' ? 'MEMBER' : 'DC';
      const payload = mode === 'new' ? {
        netbios_name: dcNetbiosName,
        upstream_forwarders: upstreams,
        global_catalog: globalCatalog,
        setup_step_ca: setupStepCa && mode !== 'join_member',
        initialize_ca: mode === 'new' && setupStepCa && initializeCa,
        ca_url: caUrl,
        ca_port: Number(caPort),
        ca_cert_hours: Number(caCertHours),
        ca_fingerprint: caFingerprint,
        cert_password: certPassword,
        tls_mode: setupStepCa ? 'step-ca' : Object.values(tlsPaths).some(Boolean) ? 'existing' : 'auto',
        tls_cert_path: tlsPaths.cert, tls_key_path: tlsPaths.key, tls_ca_path: tlsPaths.ca,
        network_interface: networkInterface,
        realm,
        workgroup,
        hostname_fqdn: dcNetbiosName.toLowerCase() + '.' + realm.toLowerCase(),
        admin_password: adminPassword,
        dns_backend: dnsBackend,
        dns_forwarder: setupBind ? '127.0.0.1:5353' : '8.8.8.8',
        setup_bind_hybrid: setupBind,
      } : {
        realm,
        target_dc_ip: targetDcIp,
        admin_username: targetAdmin,
        admin_password: adminPassword,
        netbios_name: dcNetbiosName,
        domain_role: domainRole,
        dns_backend: mode === 'join_member' ? 'NONE' : dnsBackend,
        setup_bind_hybrid: setupBind,
        clean_existing: cleanExisting,
        rejoin,
        reapply_configuration: configurationOnly,
        upstream_forwarders: upstreams,
        global_catalog: globalCatalog,
        setup_step_ca: setupStepCa && mode !== 'join_member',
        initialize_ca: mode === 'new' && setupStepCa && initializeCa,
        ca_url: caUrl,
        ca_port: Number(caPort),
        ca_cert_hours: Number(caCertHours),
        ca_fingerprint: caFingerprint,
        cert_password: certPassword,
        tls_mode: setupStepCa ? 'step-ca' : Object.values(tlsPaths).some(Boolean) ? 'existing' : 'auto',
        tls_cert_path: tlsPaths.cert, tls_key_path: tlsPaths.key, tls_ca_path: tlsPaths.ca,
        network_interface: networkInterface,
      };

      const res = await customFetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      let data = await res.json();
      let succeeded = res.ok;
      if (res.ok && data.data?.job_id) {
        localStorage.setItem('astral.provision.job', data.data.job_id);
        const result = await followProvisionJob(data.data.job_id);
        setLastResult(result);
        succeeded = result.success;
        data = { message: result.message || result.error, data: result };
      }
      if (succeeded) {
        setCompletedSteps(data.data?.steps_completed || []);
        showToast(data.message, data.data?.steps_completed?.some(item => item.startsWith('[AVISO]')) ? 'warning' : 'success');
      } else {
        setErrorMsg(data.message || 'Falha no provisionamento');
        setCompletedSteps(data.data?.steps_completed || []);
      }
    } catch (e) {
      setErrorMsg(e.message || 'Erro de comunicacao com o servidor; consulte o historico antes de repetir.');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-bold text-white tracking-wide">{t.wizardTitle}</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
        </div>

        {/* Step Indicator */}
        <div className="bg-slate-900/60 px-6 py-3 border-b border-slate-800/80 grid grid-cols-4 gap-2 text-center text-xs">
          <span className={`py-1 rounded font-medium ${step === 1 ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400'}`}>{t.wizardStep1Title}</span>
          <span className={`py-1 rounded font-medium ${step === 2 ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400'}`}>{t.wizardStep2Title}</span>
          <span className={`py-1 rounded font-medium ${step === 3 ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400'}`}>{t.wizardStep3Title}</span>
          <span className={`py-1 rounded font-medium ${step === 4 ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400'}`}>{t.wizardStep4Title}</span>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs flex-1">
          {/* STEP 1: PREFLIGHT */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="bg-emerald-950/50 border border-emerald-800/60 rounded-xl p-3.5 space-y-1">
                <span className="font-bold text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>{t.firewallSafetyNotice}</span>
                </span>
              </div>

              {loadingPreflight ? (
                <div className="text-center py-8 text-slate-400 flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                  <span>{t.preflightNotice}</span>
                </div>
              ) : preflight && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 font-mono">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 text-[11px]">FQDN:</span>
                      <div className="text-slate-200 font-bold">{preflight.fqdn}</div>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-400 text-[11px]">Endereço IP:</span>
                      <div className="text-slate-200 font-bold">{preflight.ip_address}</div>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <span className="font-bold text-slate-200">{t.adFirewallPortsLabel}:</span>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {preflight.ports_open.map((p, idx) => (
                        <div key={idx} className="bg-slate-950 border border-slate-800/80 px-2.5 py-1.5 rounded flex items-center justify-between text-[11px]">
                          <span className="font-mono text-slate-300">{p.port}/{p.proto}</span>
                          <span className={`px-1.5 py-0.2 rounded font-sans text-[10px] ${
                            p.open ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                          }`}>
                            {p.open ? t.portOpen : t.willBeAdded}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Status do DNS do Active Directory no DC2 */}
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2 mt-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-cyan-400" />
                        <span>DNS do Active Directory no Host ({dnsCheck?.hostname || 'dc2'})</span>
                      </span>
                      <button
                        type="button"
                        onClick={handleSyncDns}
                        disabled={syncingDns}
                        className="px-2.5 py-1 bg-indigo-600/80 hover:bg-indigo-600 text-white rounded text-[11px] font-medium flex items-center gap-1 transition"
                      >
                        {syncingDns ? <RefreshCw className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                        <span>Sincronizar DNS do AD</span>
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">SRV AD (_ldap):</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dnsCheck?.ad_srv_resolves ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                        }`}>
                          {dnsCheck?.ad_srv_resolves ? 'Resolvendo' : 'Pendente'}
                        </span>
                      </div>
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Registro A ({dnsCheck?.hostname || 'dc2'}):</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dnsCheck?.dc2_a_record_in_ad ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                        }`}>
                          {dnsCheck?.dc2_a_record_in_ad ? 'Registrado' : 'Pendente'}
                        </span>
                      </div>
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">DNS Autoritativo (NS):</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dnsCheck?.dc2_ns_record_in_ad ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                        }`}>
                          {dnsCheck?.dc2_ns_record_in_ad ? 'Autoritativo' : 'Pendente'}
                        </span>
                      </div>
                    </div>
                    {dnsCheck?.message && (
                      <p className="text-[11px] text-slate-400 italic">
                        {dnsCheck.message} (sem DNS externo no resolv.conf; encaminhado via BIND/Samba).
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* STEP 2: CHOOSE TOPOLOGY */}
          {step === 2 && (
            <div className="space-y-3">
              <label 
                onClick={() => { setMode('new'); setSetupStepCa(true); setInitializeCa(true); setSetupBind(true); }}
                className={`block p-4 rounded-xl border cursor-pointer transition ${
                  mode === 'new' ? 'bg-indigo-950/60 border-indigo-500 shadow-md' : 'bg-slate-950 border-slate-800'
                }`}
              >
                <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
                  <input type="radio" checked={mode === 'new'} onChange={() => { setMode('new'); setSetupStepCa(true); setInitializeCa(true); setSetupBind(true); }} />
                  <Server className="w-4 h-4 text-indigo-400" />
                  <span>{t.provisionNewDc}</span>
                </div>
                <p className="text-slate-400 text-xs mt-1 pl-6">{t.provisionNewDcDesc}</p>
              </label>

              <label 
                onClick={() => setMode('join_dc')}
                className={`block p-4 rounded-xl border cursor-pointer transition ${
                  mode === 'join_dc' ? 'bg-indigo-950/60 border-indigo-500 shadow-md' : 'bg-slate-950 border-slate-800'
                }`}
              >
                <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
                  <input type="radio" checked={mode === 'join_dc'} onChange={() => setMode('join_dc')} />
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>{t.joinExistingDc}</span>
                </div>
                <p className="text-slate-400 text-xs mt-1 pl-6">{t.joinExistingDcDesc}</p>
              </label>

              <label 
                onClick={() => setMode('join_rodc')}
                className={`block p-4 rounded-xl border cursor-pointer transition ${
                  mode === 'join_rodc' ? 'bg-indigo-950/60 border-indigo-500 shadow-md' : 'bg-slate-950 border-slate-800'
                }`}
              >
                <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
                  <input type="radio" checked={mode === 'join_rodc'} onChange={() => setMode('join_rodc')} />
                  <Lock className="w-4 h-4 text-amber-400" />
                  <span>{t.joinRodc}</span>
                </div>
                <p className="text-slate-400 text-xs mt-1 pl-6">{t.joinRodcDesc}</p>
              </label>

              <label 
                onClick={() => setMode('join_member')}
                className={`block p-4 rounded-xl border cursor-pointer transition ${
                  mode === 'join_member' ? 'bg-indigo-950/60 border-indigo-500 shadow-md' : 'bg-slate-950 border-slate-800'
                }`}
              >
                <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
                  <input type="radio" checked={mode === 'join_member'} onChange={() => setMode('join_member')} />
                  <HardDrive className="w-4 h-4 text-emerald-400" />
                  <span>{t.joinMember}</span>
                </div>
                <p className="text-slate-400 text-xs mt-1 pl-6">{t.joinMemberDesc}</p>
              </label>
            </div>
          )}

          {step === 2 && <button onClick={() => setMode('from_backup')} className={`w-full p-4 rounded-xl border text-left ${mode === 'from_backup' ? 'border-amber-500 bg-amber-950/50' : 'border-slate-700 bg-slate-950'}`}>
            <strong>Provisionar / recuperar a partir de backup</strong><p className="text-xs text-slate-400 mt-1">Importar backup Samba e recuperar o domínio em um host preparado.</p>
          </button>}
          {step === 3 && mode === 'from_backup' && <BackupProvisioning customFetch={customFetch} showToast={showToast} />}
          {step === 2 && history.length > 0 && <details className="p-3 border border-slate-700 rounded"><summary>Backups e operacoes anteriores ({history.length})</summary>{history.map(item => <div className="text-xs py-2" key={item.id}><p>{item.created_at} · {item.target_name} · {item.target_role} · {item.phase} · {item.id}</p>{item.archive_sha256 && <a className="underline text-cyan-300" href={API_BASE + "/provision/backups/" + item.id + "/download"}>Baixar backup anterior (contem segredos do dominio)</a>}<button className="mt-1 px-2 py-1 rounded bg-indigo-700" onClick={() => {setMode(item.target_role === 'RODC' ? 'join_rodc' : item.target_role === 'MEMBER' ? 'join_member' : 'join_dc');setRealm(item.realm);setDcNetbiosName(item.target_name);setTargetDcIp(item.partner || '');setUpstreamText((item.forwarders || []).join(', '));setSetupBind(!!item.setup_bind_hybrid);setGlobalCatalog(item.global_catalog !== false);setRejoin(true);setConfigurationOnly(!!item.joined);setCleanExisting(false);setStep(3);}}>Retomar com estes parametros</button></div>)}</details>}
          {/* STEP 3: PARAMETERS */}
          {step === 3 && mode !== 'from_backup' && (
            <div className="space-y-3">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Domínio Kerberos (REALM) *</label>
                <input 
                  type="text" 
                  value={realm} 
                  onChange={(e) => setRealm(e.target.value.toUpperCase())} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono uppercase focus:border-indigo-500 focus:outline-none"
                />
              </div>

              {mode === 'new' && (
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Workgroup NetBIOS *</label>
                  <input 
                    type="text" 
                    value={workgroup} 
                    onChange={(e) => setWorkgroup(e.target.value.toUpperCase())} 
                    className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono uppercase focus:border-indigo-500 focus:outline-none"
                  />
                </div>
              )}

              {mode !== 'new' && (
                <div className="space-y-2">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">
                      {mode === 'join_member' ? 'Nome NetBIOS da Máquina (Hostname) *' : mode === 'join_rodc' ? 'Nome NetBIOS do RODC *' : 'Nome NetBIOS do DC Réplica (Hostname do DC) *'}
                    </label>
                    <input 
                      type="text" 
                      value={dcNetbiosName} 
                      onChange={(e) => setDcNetbiosName(e.target.value.toUpperCase())} 
                      placeholder="DC2 (ou outro nome desejado)"
                      className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono uppercase focus:border-indigo-500 focus:outline-none"
                    />
                    <span className="text-[10px] text-slate-400 mt-0.5 block">
                      Permite definir ou alterar o nome NetBIOS para evitar conflitos com nomes já provisionados.
                    </span>
                  </div>

                  <div>
                    <label className="block text-slate-300 font-medium mb-1">IP do DC Primário (DC1) *</label>
                    <input 
                      type="text" 
                      value={targetDcIp} 
                      onChange={(e) => setTargetDcIp(e.target.value)}
                      placeholder="Informe o IPv4 do DC existente"
                      required
                      className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 font-mono focus:border-indigo-500 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Usuário Administrador do Domínio *</label>
                    <input 
                      type="text" 
                      value={targetAdmin} 
                      onChange={(e) => setTargetAdmin(e.target.value)} 
                      placeholder="administrator"
                      className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                    />
                  </div>

                  {mode === 'join_member' && (
                    <div className="bg-emerald-950/40 border border-emerald-800/60 p-3 rounded-lg text-emerald-300 text-xs flex items-start gap-2">
                      <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold">Modo Servidor Membro (Bind):</span> A máquina será associada ao domínio Active Directory para compartilhamento e serviços autenticados via Winbind / PAM. O daemon de AD DC fica mascarado e não replica a base NTDS.
                      </div>
                    </div>
                  )}

                  {mode === 'join_rodc' && (
                    <div className="bg-amber-950/40 border border-amber-800/60 p-3 rounded-lg text-amber-300 text-xs flex items-start gap-2">
                      <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold">Modo RODC (Read-Only DC):</span> O controlador receberá réplica unidirecional somente leitura. Senhas de usuários e contas administrativas permanecem seguras fora deste host.
                      </div>
                    </div>
                  )}

                  {(mode === 'join_dc' || mode === 'join_rodc') && (
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                          <Globe className="w-3.5 h-3.5 text-cyan-400" />
                          <span>DNS do AD no Host:</span>
                        </span>
                        <button
                          type="button"
                          onClick={handleSyncDns}
                          disabled={syncingDns}
                          className="px-2 py-0.5 bg-indigo-600/80 hover:bg-indigo-600 text-white rounded text-[10px] transition flex items-center gap-1"
                        >
                          {syncingDns ? <RefreshCw className="w-2.5 h-2.5 animate-spin" /> : <RefreshCw className="w-2.5 h-2.5" />}
                          Sincronizar DNS
                        </button>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dnsCheck?.ad_srv_resolves ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                        }`}>
                          SRV AD: {dnsCheck?.ad_srv_resolves ? 'Resolvendo' : 'Pendente'}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dnsCheck?.dc2_a_record_in_ad ? 'text-emerald-400 bg-emerald-950' : 'text-amber-400 bg-amber-950'
                        }`}>
                          Registro A: {dnsCheck?.dc2_a_record_in_ad ? 'Registrado' : 'Pendente'}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[10px]">
                        Consulta diretamente o DNS do DC parceiro informado ({targetDcIp || "IP obrigatorio"}:53). O BIND local em 127.0.0.1:5353 e opcional e nao e usado para descobrir o AD.
                      </p>
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">{t.adminPasswordLabel} *</label>
                <input 
                  type="password" 
                  value={adminPassword} 
                  onChange={(e) => setAdminPassword(e.target.value)} 
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg text-slate-100 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              {/* Seleção do Backend DNS (para New DC, Join DC e Join RODC) */}
              {mode !== 'join_member' && (
                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <label className="block text-slate-300 font-medium">{t.dnsBackendLabel || "Backend DNS"}</label>
                  <div className="p-2.5 rounded-lg border border-indigo-500 bg-indigo-950/60">
                    <strong>SAMBA_INTERNAL · AD DNS :53</strong>
                    <p className="text-[10px] text-slate-400">{t.dnsBackendInternalDesc}</p>
                  </div>

                  {dnsBackend === 'SAMBA_INTERNAL' && (
                    <div className="space-y-1 pt-1">
                      <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                        <input 
                          type="checkbox" 
                          checked={setupBind} 
                          onChange={(e) => setSetupBind(e.target.checked)} 
                          className="rounded bg-slate-950 border-slate-700 text-indigo-600"
                        />
                        <span>{t.bindHybridOption}</span>
                      </label>
                      <span className="text-[10px] text-slate-400 block pl-6">
                        O ingresso usa o IP do DC parceiro na porta 53. Esta opcao configura recursao local adicional em 127.0.0.1:5353; so sera ativada depois de validada.
                      </span>
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-3 border-t border-slate-800 pt-3">
                <label className="block text-slate-300">Forwarders DNS (IPv4/IPv6 separados por virgula)
                  <input aria-label="Forwarders DNS do provisionamento" value={upstreamText} onChange={event => setUpstreamText(event.target.value)} className="mt-1 w-full bg-slate-950 border border-slate-700 p-2 rounded" />
                </label>
                <label className="block text-slate-300">Interface de rede (opcional)
                  <input aria-label="Interface de rede Samba" value={networkInterface} onChange={event => setNetworkInterface(event.target.value)} placeholder="Ex.: enp3s0; vazio usa as interfaces atuais" className="mt-1 w-full bg-slate-950 border border-slate-700 p-2 rounded" />
                </label>
                {mode !== 'join_member' && <>
                  <p>{mode === 'new' ? 'DC1: a CA e os certificados sao gerados e configurados automaticamente. Informe apenas a senha da PKI abaixo.' : 'Certificados existentes sao detectados automaticamente. Informe caminhos somente se desejar selecionar outro conjunto.'}</p>
                  {!setupStepCa && <details><summary>Avancado: selecionar certificados existentes no servidor</summary>{['cert', 'key', 'ca'].map(field => <input key={field} aria-label={'TLS ' + field} placeholder={field === 'cert' ? 'Certificado deste DC (.pem/.crt)' : field === 'key' ? 'Chave privada deste DC (.key)' : 'Cadeia CA completa (.pem/.crt)'} value={tlsPaths[field]} onChange={event => setTlsPaths({...tlsPaths, [field]: event.target.value})} className="w-full bg-slate-950 border border-slate-700 p-2 rounded" />)}</details>}
                  <label className="flex gap-2"><input type="checkbox" checked={setupStepCa} onChange={event => setSetupStepCa(event.target.checked)} />Configurar certificado LDAPS e renovacao via Step-CA</label>
                  {setupStepCa && <div className="space-y-2 pl-4">
                    {mode === 'new' && <label className="flex gap-2"><input type="checkbox" checked={initializeCa} onChange={event => setInitializeCa(event.target.checked)} />Inicializar CA neste novo dominio (preserva qualquer CA existente)</label>}
                    <label className="block">Porta preferida da nova CA (escolhe outra livre e abre automaticamente)<input type="number" min="1024" max="65535" aria-label="Porta da CA" value={caPort} onChange={event => setCaPort(event.target.value)} className="ml-2 bg-slate-950 border border-slate-700 p-2 rounded" /></label>
                    <label className="block">Validade solicitada do certificado (horas)<input type="number" min="1" max="8760" aria-label="Validade do certificado" value={caCertHours} onChange={event => setCaCertHours(event.target.value)} className="ml-2 bg-slate-950 border border-slate-700 p-2 rounded" /></label>
                    <input aria-label="URL da CA" value={caUrl} onChange={event => setCaUrl(event.target.value)} placeholder="URL HTTPS da CA; vazio usa a CA local" className="w-full bg-slate-950 border border-slate-700 p-2 rounded" />
                    <input aria-label="Fingerprint SHA256 da CA" value={caFingerprint} onChange={event => setCaFingerprint(event.target.value)} placeholder="Fingerprint SHA256 para CA remota" className="w-full bg-slate-950 border border-slate-700 p-2 rounded" />
                    <input type="password" aria-label="Senha da PKI" value={certPassword} onChange={event => setCertPassword(event.target.value)} placeholder="Senha da PKI (nao e salva no navegador)" className="w-full bg-slate-950 border border-slate-700 p-2 rounded" />
                  </div>}
                </>}
                <p className="text-xs text-slate-400">Pacotes ausentes, NTP, iptables e persistencia das regras sao tratados automaticamente. O BIND local usa estes forwarders quando selecionado.</p>
                {mode !== 'new' && <>
                  <label className="flex gap-2"><input type="checkbox" checked={rejoin} onChange={event => setRejoin(event.target.checked)} />Reingresso com backup automatico, despromocao e limpeza antes do novo papel</label>
                  <label className="flex gap-2"><input type="checkbox" checked={configurationOnly} onChange={event => setConfigurationOnly(event.target.checked)} />Reaplicar configuracao sem refazer o ingresso</label>
                </>}
                {mode !== 'join_member' && <label className="flex gap-2"><input type="checkbox" checked={globalCatalog} onChange={event => setGlobalCatalog(event.target.checked)} />Ativar e verificar catalogo global (3268/3269)</label>}
              </div>

              {/* Opções de Limpeza de Estado Anterior */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                  <input 
                    type="checkbox" 
                    checked={cleanExisting} 
                    onChange={(e) => setCleanExisting(e.target.checked)} 
                    className="rounded bg-slate-950 border-slate-700 text-indigo-600"
                  />
                  <span className="font-medium text-amber-300">Permitir remover somente a conta orfa deste servidor se a despromocao normal falhar</span>
                </label>

              </div>

              {mode === 'new' && (
                <div className="space-y-2 pt-2">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                    <input type="checkbox" checked={true} readOnly className="rounded bg-slate-950 border-slate-700 text-indigo-600" />
                    <span>{t.chronySignedOption}</span>
                  </label>
                </div>
              )}
            </div>
          )}

          {/* STEP 4: EXECUTION PROGRESS */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                {executing && <RefreshCw className="w-5 h-5 animate-spin text-indigo-400" />}
                {!executing && !errorMsg && <CheckCircle className="w-5 h-5 text-emerald-400" />}
                {!executing && errorMsg && <AlertTriangle className="w-5 h-5 text-rose-400" />}
                <h4 className="font-bold text-sm text-slate-100">
                  {executing ? t.provisioningInProgress : errorMsg ? t.provisionErrorTitle : t.provisionSuccessTitle}
                </h4>
              </div>

              {errorMsg && (
                <div className="bg-rose-950/80 border border-rose-800 p-3 rounded-lg text-rose-200 font-mono">
                  {errorMsg}
                </div>
              )}

              {lastResult?.ca_url && <a className="text-cyan-300 underline" href={lastResult.ca_url} target="_blank" rel="noopener noreferrer">CA configurada: {lastResult.ca_url}</a>}
              {lastResult?.backup_path && <p className="text-xs text-slate-300 break-all">Backup automatico: {lastResult.backup_path}</p>}
              {!executing && lastResult && !lastResult.success && <button className="px-3 py-2 rounded bg-indigo-600" onClick={() => { setRejoin(true); setConfigurationOnly(!!lastResult.joined); if ((lastResult.message || lastResult.error || '').includes('Despromocao nao concluiu')) setCleanExisting(true); setStep(3); }}>Retomar pela interface</button>}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5 font-mono text-[11px]">
                {completedSteps.map((st, i) => (
                  <div key={i} className={`flex items-center gap-2 ${st.startsWith("[AVISO]") ? "text-amber-400" : "text-emerald-400"}`}>
                    {st.startsWith("[AVISO]") ? <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> : <CheckCircle className="w-3.5 h-3.5 shrink-0" />}
                    <span>{st}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="bg-slate-950 px-6 py-3 border-t border-slate-800 flex justify-between items-center text-xs">
          {step > 1 && step < 4 && (
            <button 
              onClick={() => setStep(step - 1)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
            >
              Voltar
            </button>
          )}
          {step === 1 && <div />}

          <div className="flex items-center gap-2">
            <button 
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
            >
              {step === 4 ? t.stepClose : t.cancel}
            </button>
            {step < 3 && (
              <button 
                onClick={() => setStep(step + 1)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition"
              >
                Avançar
              </button>
            )}
            {step === 3 && mode !== 'from_backup' && (
              <button 
                onClick={handleStartProvision}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition shadow-md"
              >
                {t.startProvisioning}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


function TerminalTab({ t, operator, showToast, customFetch }) {
  const isDenied = operator?.provider === 'Postgres';
  const [lines, setLines] = useState([
    { output: 'Astral AD & Hybrid DNS Management Console [Terminal]' },
    { output: 'Ambiente autorizado para intervenções pontuais do Active Directory, BIND 9 e SO.' }
  ]);
  const [cmd, setCmd] = useState('');
  const [loading, setLoading] = useState(false);
  const endRef = React.useRef(null);

  React.useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const handleExec = async (e) => {
    if (e) e.preventDefault();
    const trimmed = cmd.trim();
    if (!trimmed || loading) return;

    if (trimmed === 'clear') {
      setLines([]);
      setCmd('');
      return;
    }

    const current = trimmed;
    setCmd('');
    setLoading(true);
    setLines(prev => [...prev, { cmd: current }]);

    try {
      const res = await customFetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: current })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        const out = (data.stdout || '') + (data.stderr ? ((data.stdout ? '\n' : '') + data.stderr) : '');
        setLines(prev => [...prev, { output: out || '(Sem saída)' }]);
      } else {
        setLines(prev => [...prev, { output: data.error || 'Erro na execução', isError: true }]);
        showToast(data.error || 'Erro ao executar comando', 'error');
      }
    } catch (err) {
      setLines(prev => [...prev, { output: err.message || 'Erro de rede', isError: true }]);
      showToast('Erro de rede', 'error');
    } finally {
      setLoading(false);
    }
  };

  if (isDenied) {
    return (
      <div className="p-8 max-w-2xl mx-auto">
        <div className="bg-rose-950/40 border border-rose-800/80 rounded-2xl p-6 text-rose-200">
          <div className="flex items-center gap-3 mb-3">
            <AlertTriangle className="w-8 h-8 text-rose-400" />
            <h3 className="text-lg font-bold text-rose-100">Acesso ao Terminal Negado</h3>
          </div>
          <p className="text-sm leading-relaxed mb-4">
            {t.terminalDenied || "O terminal do sistema operacional é restrito exclusivamente a administradores do Samba Active Directory ou operadores Linux (sudo/root)."}
          </p>
          <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-400">
            Operador atual: <strong>{operator?.username}</strong> &bull; Provedor: <strong>{operator?.provider}</strong> (Permissão restrita a operações de banco de dados).
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 flex flex-col h-[calc(100vh-140px)]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            {t.terminal || 'Terminal do Sistema'}
          </h2>
          <p className="text-xs text-slate-400">{t.terminalDesc || 'Console operacional para intervenções pontuais na infraestrutura.'}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono">
            {operator?.username} ({operator?.provider})
          </span>
          <button
            onClick={() => setLines([])}
            className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition cursor-pointer"
          >
            {t.clearTerminal || 'Limpar'}
          </button>
        </div>
      </div>

      <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-y-auto font-mono text-sm flex flex-col justify-between shadow-inner">
        <div className="space-y-2">
          {lines.map((l, idx) => (
            <div key={idx}>
              {l.cmd && (
                <div className="text-sky-400 font-semibold flex items-center gap-1.5">
                  <span className="text-emerald-400">[{operator?.username}@dc-erp ~]$</span>
                  <span className="text-slate-100">{l.cmd}</span>
                </div>
              )}
              {l.output && (
                <pre className={`text-xs whitespace-pre-wrap break-all ${l.isError ? 'text-rose-400' : 'text-slate-300'}`}>
                  {l.output}
                </pre>
              )}
            </div>
          ))}
          <div ref={endRef} />
        </div>

        <form onSubmit={handleExec} className="mt-4 pt-3 border-t border-slate-800/80 flex items-center gap-2">
          <span className="text-emerald-400 font-semibold text-xs whitespace-nowrap">
            [{operator?.username}@dc-erp ~]$
          </span>
          <input
            type="text"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            disabled={loading}
            placeholder={t.terminalPrompt || 'Digite um comando...'}
            className="flex-1 bg-slate-900 border border-slate-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none"
            autoFocus
          />
          <button
            type="submit"
            disabled={loading || !cmd.trim()}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 transition cursor-pointer flex items-center gap-1"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ArrowRight className="w-3.5 h-3.5" />}
            <span>Executar</span>
          </button>
        </form>
      </div>
    </div>
  );
}
