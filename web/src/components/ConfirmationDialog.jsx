import React, { useEffect, useRef, useState } from 'react';

// Native confirm() is suppressed in cross-origin/sandboxed portal frames.
// Keep confirmations in the application's document instead.
const requests = new EventTarget();
export function confirmAction(message, options = {}) {
  return new Promise(resolve => requests.dispatchEvent(new CustomEvent('confirm', {
    detail: { message, options, resolve },
  })));
}

export default function ConfirmationDialog() {
  const [request, setRequest] = useState(null);
  const pending = useRef(null);
  const cancelButton = useRef(null);
  const previousFocus = useRef(null);
  const finish = value => {
    pending.current?.resolve(value);
    pending.current = null;
    setRequest(null);
    previousFocus.current?.focus();
  };
  useEffect(() => {
    const open = event => {
      pending.current?.resolve(false);
      previousFocus.current = document.activeElement;
      pending.current = event.detail;
      setRequest(event.detail);
    };
    requests.addEventListener('confirm', open);
    return () => {
      requests.removeEventListener('confirm', open);
      pending.current?.resolve(false);
    };
  }, []);
  useEffect(() => { if (request) cancelButton.current?.focus(); }, [request]);
  if (!request) return null;
  return (
    <div className="fixed inset-0 z-[100] bg-slate-950/90 flex items-center justify-center p-4">
      <section role="alertdialog" aria-modal="true" aria-labelledby="confirmation-title" aria-describedby="confirmation-message"
        onKeyDown={event => {
          if (event.key === 'Escape') finish(false);
          if (event.key === 'Tab') {
            const buttons = event.currentTarget.querySelectorAll('button');
            const first = buttons[0], last = buttons[buttons.length - 1];
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
          }
        }}
        className="max-w-lg w-full bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-2xl">
        <h2 id="confirmation-title" className="font-bold text-slate-100">{request.options.title || 'Confirmar operação'}</h2>
        <p id="confirmation-message" className="text-sm text-slate-300 whitespace-pre-wrap break-words my-5">{request.message}</p>
        <div className="flex justify-end gap-3">
          <button ref={cancelButton} onClick={() => finish(false)} className="px-4 py-2 rounded bg-slate-800 text-slate-200">{request.options.cancelLabel || 'Cancelar'}</button>
          <button onClick={() => finish(true)} className="px-4 py-2 rounded bg-rose-700 text-white">{request.options.confirmLabel || 'Confirmar'}</button>
        </div>
      </section>
    </div>
  );
}
