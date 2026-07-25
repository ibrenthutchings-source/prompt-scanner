/**
 * Shadow-DOM UI kit shared by every site's content script.
 *
 * Everything renders inside a closed-ish shadow root so the host page's CSS
 * can't bleed in (and ours can't leak out). This is the surface that makes a
 * BLOCK verdict visible: an unmissable modal the user cannot click through,
 * distinct from a WARN toast they can dismiss and continue past.
 */
(function () {
  if (window.__pgOverlay) return; // idempotent across re-injection
  const HOST_ID = "pg-overlay-host";

  function ensureHost() {
    let host = document.getElementById(HOST_ID);
    if (host) return host.shadowRoot;
    host = document.createElement("div");
    host.id = HOST_ID;
    host.className = "pg-host";
    document.documentElement.appendChild(host);
    const root = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.appendChild(style);
    return root;
  }

  const STYLE = `
    :host, * { box-sizing: border-box; }
    .pg-toast {
      display: flex; align-items: flex-start; gap: 10px;
      width: 360px; margin-top: 10px; padding: 12px 14px;
      border-radius: 12px; box-shadow: 0 6px 24px rgba(0,0,0,.25);
      font-size: 13px; line-height: 1.45; color: #fff;
      animation: pg-in .18s ease-out;
    }
    .pg-toast.warn { background: #7a5b00; border: 1px solid #fab219; }
    .pg-toast.redact { background: #6b3a1f; border: 1px solid #ec835a; }
    .pg-toast.error { background: #3a3a38; border: 1px solid #898781; }
    .pg-toast .pg-icon { font-size: 16px; flex-shrink: 0; }
    .pg-toast .pg-body { flex: 1; }
    .pg-toast .pg-title { font-weight: 700; margin-bottom: 2px; }
    .pg-toast button.pg-x {
      background: none; border: none; color: inherit; opacity: .7;
      cursor: pointer; font-size: 14px; padding: 0 0 0 6px;
    }
    .pg-modal-backdrop {
      position: fixed; inset: 0; background: rgba(10,10,10,.55);
      display: flex; align-items: center; justify-content: center;
      z-index: 2147483647;
    }
    .pg-modal {
      width: min(480px, 92vw); background: #1a1a19; color: #fff;
      border: 1px solid #d03b3b; border-radius: 16px; padding: 22px 24px;
      box-shadow: 0 20px 60px rgba(0,0,0,.5);
      animation: pg-pop .16s ease-out;
    }
    .pg-modal-head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
    .pg-modal-icon {
      width: 30px; height: 30px; border-radius: 50%; background: #d03b3b;
      display: flex; align-items: center; justify-content: center; font-weight: 900;
      flex-shrink: 0;
    }
    .pg-modal-title { font-size: 16px; font-weight: 800; }
    .pg-modal-body { font-size: 13.5px; line-height: 1.55; color: #e5e4de; }
    .pg-findings { margin: 14px 0 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 6px; }
    .pg-findings li {
      font-size: 12px; background: #232322; border: 1px solid #383835;
      border-radius: 8px; padding: 6px 10px; display: flex; gap: 8px; align-items: center;
    }
    .pg-sev {
      font-size: 10px; font-weight: 800; text-transform: uppercase;
      padding: 1px 6px; border-radius: 999px; background: #d03b3b; color: #fff; flex-shrink: 0;
    }
    .pg-modal-footer { margin-top: 18px; display: flex; justify-content: flex-end; gap: 8px; }
    .pg-btn {
      border: none; border-radius: 8px; padding: 8px 16px; font-weight: 700;
      font-size: 13px; cursor: pointer;
    }
    .pg-btn.primary { background: #fff; color: #0b0b0b; }
    .pg-event-id { font-size: 11px; color: #898781; margin-top: 10px; font-family: ui-monospace, monospace; }
    @keyframes pg-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
    @keyframes pg-pop { from { opacity: 0; transform: scale(.96); } to { opacity: 1; transform: none; } }
  `;

  function toast({ kind, icon, title, body, timeoutMs = 6000 }) {
    const root = ensureHost();
    const el = document.createElement("div");
    el.className = `pg-toast ${kind}`;
    el.innerHTML = `
      <span class="pg-icon">${icon}</span>
      <div class="pg-body">
        <div class="pg-title">${escapeHtml(title)}</div>
        <div>${escapeHtml(body)}</div>
      </div>
      <button class="pg-x" aria-label="Dismiss">✕</button>
    `;
    root.appendChild(el);
    const remove = () => el.remove();
    el.querySelector(".pg-x").addEventListener("click", remove);
    if (timeoutMs > 0) setTimeout(remove, timeoutMs);
    return remove;
  }

  function showBlocked(verdict) {
    const root = ensureHost();
    const backdrop = document.createElement("div");
    backdrop.className = "pg-modal-backdrop";
    const findings = (verdict.findings || [])
      .slice(0, 6)
      .map(
        (f) =>
          `<li><span class="pg-sev">${escapeHtml(f.severity)}</span><span>${escapeHtml(
            f.title,
          )}</span></li>`,
      )
      .join("");
    backdrop.innerHTML = `
      <div class="pg-modal" role="alertdialog" aria-modal="true">
        <div class="pg-modal-head">
          <div class="pg-modal-icon">✕</div>
          <div class="pg-modal-title">Prompt blocked by security policy</div>
        </div>
        <div class="pg-modal-body">${escapeHtml(verdict.message || "This prompt was blocked.")}</div>
        ${findings ? `<ul class="pg-findings">${findings}</ul>` : ""}
        <div class="pg-event-id">Event ${escapeHtml(verdict.event_id || "unknown")}</div>
        <div class="pg-modal-footer">
          <button class="pg-btn primary" data-action="close">Understood</button>
        </div>
      </div>
    `;
    root.appendChild(backdrop);
    const close = () => backdrop.remove();
    backdrop.querySelector('[data-action="close"]').addEventListener("click", close);
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) close();
    });
    document.addEventListener(
      "keydown",
      function onEsc(e) {
        if (e.key === "Escape") {
          close();
          document.removeEventListener("keydown", onEsc);
        }
      },
      { once: false },
    );
  }

  function showWarning(verdict) {
    toast({
      kind: "warn",
      icon: "▲",
      title: "Sensitive content detected",
      body: verdict.message || "This prompt was flagged for review.",
    });
  }

  function showRedacted(verdict) {
    toast({
      kind: "redact",
      icon: "▤",
      title: "Sensitive values masked",
      body: "Review the masked text in the composer, then send again.",
      timeoutMs: 8000,
    });
  }

  function showError(message) {
    toast({ kind: "error", icon: "!", title: "Prompt Gateway unavailable", body: message });
  }

  function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c]);
  }

  window.__pgOverlay = { showBlocked, showWarning, showRedacted, showError, toast };
})();
