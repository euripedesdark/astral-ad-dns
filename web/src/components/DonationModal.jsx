import React, { useState } from "react";
import { Heart, Copy, Check, X, Globe, Shield } from "lucide-react";

const DONATION_DATA = {
  pix: "24adc62c-b073-4587-974d-03fe35f6733f",
  wise: {
    name: "Euripedes Batista de Paiva Junior",
    type: "Checking",
    routing: "101019628",
    account: "215822927677",
    bank: "Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States",
    swift: "TRWIUS35XXX"
  }
};

const TEXTS = {
  pt: {
    title: "Apoie o Astral AD & Hybrid DNS",
    subtitle: "Astral AD & DNS é uma solução Open Source de identidade corporativa e resolução DNS mantida por um único desenvolvedor.",
    pixTitle: "PIX (Brasil)",
    pixDesc: "Copie a chave aleatória abaixo para realizar uma doação instantânea via PIX:",
    copyPix: "Copiar Chave PIX",
    copied: "Copiado para a área de transferência!",
    wiseTitle: "Transferência Internacional (Wise)",
    wiseDesc: "Para transferências dos Estados Unidos (ACH/Wire) ou de qualquer outro país via SWIFT:",
    name: "Titular / Beneficiário",
    type: "Tipo de Conta",
    routing: "Routing Number (ACH / Wire)",
    account: "Número da Conta",
    bank: "Banco e Endereço",
    swift: "Código SWIFT / BIC",
    note: "O Routing Number aplica-se a transferências originadas nos EUA. Para outros países, utilize o código SWIFT/BIC.",
    close: "Fechar"
  },
  en: {
    title: "Support Astral AD & Hybrid DNS",
    subtitle: "Astral AD & DNS is an open-source enterprise identity and DNS resolution platform maintained by a single developer.",
    pixTitle: "PIX (Instant Transfer - Brazil)",
    pixDesc: "Copy the random PIX key below for instant transfer in Brazil:",
    copyPix: "Copy PIX Key",
    copied: "Copied to clipboard!",
    wiseTitle: "International Bank Transfer (Wise)",
    wiseDesc: "For domestic US transfers (ACH/Wire) or international transfers via SWIFT worldwide:",
    name: "Account Holder",
    type: "Account Type",
    routing: "Routing Number (ACH / Wire)",
    account: "Account Number",
    bank: "Bank Name & Address",
    swift: "SWIFT / BIC Code",
    note: "The Routing Number applies to transfers within the US. For transfers outside the US, please use SWIFT/BIC.",
    close: "Close"
  },
  es: {
    title: "Apoya a Astral AD & Hybrid DNS",
    subtitle: "Astral AD & DNS es una plataforma de identidad corporativa y DNS de código abierto desarrollada por un único programador.",
    pixTitle: "PIX (Brasil)",
    pixDesc: "Copia la clave aleatoria a continuación para donar al instante mediante PIX:",
    copyPix: "Copiar Clave PIX",
    copied: "¡Copiado al portapapeles!",
    wiseTitle: "Transferencia Internacional (Wise)",
    wiseDesc: "Para transferencias domésticas desde EE.UU. (ACH/Wire) o internacionales vía SWIFT:",
    name: "Titular / Beneficiario",
    type: "Tipo de Cuenta",
    routing: "Routing Number (ACH / Wire)",
    account: "Número de Cuenta",
    bank: "Nombre y Dirección del Banco",
    swift: "Código SWIFT / BIC",
    note: "El Routing Number se utiliza en envíos dentro de EE.UU. Fuera de allí, utiliza el código SWIFT/BIC.",
    close: "Cerrar"
  },
  fr: {
    title: "Soutenez Astral AD & Hybrid DNS",
    subtitle: "Astral AD & DNS est une solution open source d'identité d'entreprise et de DNS développée par un seul contributeur.",
    pixTitle: "PIX (Brésil)",
    pixDesc: "Copiez la clé aléatoire ci-dessous pour faire un don instantané via PIX :",
    copyPix: "Copier la clé PIX",
    copied: "Copié dans le presse-papiers !",
    wiseTitle: "Virement bancaire international (Wise)",
    wiseDesc: "Pour les virements depuis les États-Unis (ACH/Wire) ou depuis le monde entier via SWIFT :",
    name: "Titulaire du compte",
    type: "Type de compte",
    routing: "Routing Number (ACH / Wire)",
    account: "Numéro de compte",
    bank: "Nom et adresse de la banque",
    swift: "Code SWIFT / BIC",
    note: "Le Routing Number est utilisé aux États-Unis. Ailleurs, utilisez le code SWIFT/BIC.",
    close: "Fermer"
  }
};

export default function DonationModal({ isOpen, onClose, lang = "pt" }) {
  if (!isOpen) return null;
  const currentLang = (lang && ["pt", "en", "es", "fr"].includes(lang)) ? lang : "pt";
  const text = TEXTS[currentLang] || TEXTS.pt;
  const [copiedField, setCopiedField] = useState(null);

  const copyToClipboard = (val, field) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(val);
    }
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400">
              <Heart className="w-6 h-6 fill-rose-500" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-wide">{text.title}</h3>
              <p className="text-xs text-slate-400 line-clamp-1">{text.subtitle}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="mt-5 space-y-4 max-h-[75vh] overflow-y-auto pr-1">
          {/* PIX */}
          <div className="p-4 bg-slate-800/60 border border-slate-700/60 rounded-xl">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="text-lg">🇧🇷</span>
                <span className="font-semibold text-sky-400 text-sm">{text.pixTitle}</span>
              </div>
              {copiedField === "pix" && (
                <span className="text-xs text-emerald-400 font-medium flex items-center gap-1">
                  <Check className="w-3.5 h-3.5" /> {text.copied}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mb-3">{text.pixDesc}</p>
            <div className="flex items-center gap-2 p-2 bg-slate-950/80 rounded-lg border border-slate-800">
              <code className="flex-1 font-mono text-xs text-emerald-400 select-all break-all px-2">
                {DONATION_DATA.pix}
              </code>
              <button
                onClick={() => copyToClipboard(DONATION_DATA.pix, "pix")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                  copiedField === "pix"
                    ? "bg-emerald-600 text-white"
                    : "bg-sky-600 hover:bg-sky-500 text-white"
                }`}
              >
                {copiedField === "pix" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedField === "pix" ? "" : text.copyPix}</span>
              </button>
            </div>
          </div>

          {/* WISE */}
          <div className="p-4 bg-slate-800/60 border border-slate-700/60 rounded-xl">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="w-4 h-4 text-purple-400" />
              <span className="font-semibold text-purple-300 text-sm">{text.wiseTitle}</span>
            </div>
            <p className="text-xs text-slate-400 mb-3">{text.wiseDesc}</p>

            <div className="overflow-hidden rounded-lg border border-slate-800 text-xs">
              <table className="w-full text-left border-collapse">
                <tbody className="divide-y divide-slate-800">
                  <tr className="bg-slate-950/40">
                    <td className="py-2 px-3 text-slate-400 w-1/3">{text.name}</td>
                    <td className="py-2 px-3 text-white font-medium">{DONATION_DATA.wise.name}</td>
                    <td className="py-2 px-2 text-right">
                      <button onClick={() => copyToClipboard(DONATION_DATA.wise.name, "name")} className="text-slate-400 hover:text-white p-1 cursor-pointer">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 text-slate-400">{text.type}</td>
                    <td className="py-2 px-3 text-slate-200" colSpan={2}>{DONATION_DATA.wise.type}</td>
                  </tr>
                  <tr className="bg-slate-950/40">
                    <td className="py-2 px-3 text-slate-400">{text.routing}</td>
                    <td className="py-2 px-3 font-mono text-emerald-400 font-semibold">{DONATION_DATA.wise.routing}</td>
                    <td className="py-2 px-2 text-right">
                      <button onClick={() => copyToClipboard(DONATION_DATA.wise.routing, "routing")} className="text-slate-400 hover:text-white p-1 cursor-pointer">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 text-slate-400">{text.account}</td>
                    <td className="py-2 px-3 font-mono text-emerald-400 font-semibold">{DONATION_DATA.wise.account}</td>
                    <td className="py-2 px-2 text-right">
                      <button onClick={() => copyToClipboard(DONATION_DATA.wise.account, "account")} className="text-slate-400 hover:text-white p-1 cursor-pointer">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                  <tr className="bg-slate-950/40">
                    <td className="py-2 px-3 text-slate-400">{text.swift}</td>
                    <td className="py-2 px-3 font-mono text-sky-400 font-semibold">{DONATION_DATA.wise.swift}</td>
                    <td className="py-2 px-2 text-right">
                      <button onClick={() => copyToClipboard(DONATION_DATA.wise.swift, "swift")} className="text-slate-400 hover:text-white p-1 cursor-pointer">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 text-slate-400">{text.bank}</td>
                    <td className="py-2 px-3 text-slate-300 text-[11px]" colSpan={2}>{DONATION_DATA.wise.bank}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <p className="mt-2 text-[11px] text-slate-500 italic">
              ℹ️ {text.note}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition cursor-pointer"
          >
            {text.close}
          </button>
        </div>
      </div>
    </div>
  );
}
