/**
 * Generic "intercept the send action, scan first" state machine, shared by
 * every site-specific content script. A site script just supplies selectors
 * and DOM adapters; this file owns the interception + verdict handling so
 * that logic lives in exactly one place.
 *
 * Two send paths exist on every one of these sites — pressing Enter in the
 * composer, and clicking the send button — and a user can trigger either.
 * We hook both at the document capture phase so we see the event before the
 * site's own React/framework handlers do, and can preventDefault() before
 * anything gets transmitted.
 */
(function () {
  if (window.__pgCreateGuard) return;

  /**
   * Replace a contenteditable region's content in a way frameworks notice.
   * Directly setting `.textContent` does NOT fire the input events
   * ProseMirror/Quill/Lexical listen for, so their internal model silently
   * disagrees with the DOM and either reverts the change or desyncs. Select
   * all + execCommand('insertText') fires the same native input pipeline a
   * real paste would, which every one of these editors already handles.
   */
  function replaceContentEditable(el, text) {
    el.focus();
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    const ok = document.execCommand("insertText", false, text);
    if (!ok) {
      // Fallback for browsers/contexts where execCommand is unavailable.
      el.textContent = text;
      el.dispatchEvent(new InputEvent("input", { bubbles: true, data: text }));
    }
  }

  function setTextareaValue(el, text) {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      "value",
    ).set;
    setter.call(el, text);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function defaultSetText(el, text) {
    if (el.tagName === "TEXTAREA") setTextareaValue(el, text);
    else replaceContentEditable(el, text);
  }

  function defaultGetText(el) {
    if (el.tagName === "TEXTAREA") return el.value;
    return el.innerText;
  }

  /**
   * @param {object} config
   * @param {string} config.siteName - "chatgpt" | "claude" | "gemini"
   * @param {string} [config.provider]
   * @param {() => Element|null} config.getComposer
   * @param {(el: Element) => string} [config.getText]
   * @param {(el: Element, text: string) => void} [config.setText]
   * @param {(e: KeyboardEvent, composer: Element) => boolean} config.isSendKeydown
   * @param {() => Element|null} [config.getSendButton]
   * @param {() => void} config.triggerSend - re-issue the send once we've decided to allow it
   */
  function createGuard(config) {
    const getText = config.getText || defaultGetText;
    const setText = config.setText || defaultSetText;
    let scanning = false;

    async function handleSend(evt, composer) {
      const text = getText(composer);
      if (!text || !text.trim()) return; // nothing to scan; let it through untouched
      evt.preventDefault();
      evt.stopImmediatePropagation();
      scanning = true;
      try {
        const resp = await window.__pgScan.scanPrompt({
          text,
          site: config.siteName,
          provider: config.provider || null,
          url: location.href,
        });

        if (!resp.ok) {
          // Fail open: a gateway outage should degrade to "unmonitored", not
          // "employee can't use the tool they're paid to use". The outage
          // itself is visible in the toast and in the gateway's own alerting
          // on the next successful heartbeat check from an admin.
          window.__pgOverlay.showError(resp.error);
          config.triggerSend();
          return;
        }
        if (resp.skipped) {
          config.triggerSend();
          return;
        }

        const verdict = resp.verdict;
        if (verdict.action === "block") {
          window.__pgOverlay.showBlocked(verdict);
          return; // never call triggerSend — this is the whole point
        }
        if (verdict.action === "redact" && verdict.redacted_text) {
          setText(composer, verdict.redacted_text);
          window.__pgOverlay.showRedacted(verdict);
          return; // let the user review and press send again themselves
        }
        if (verdict.action === "warn") {
          window.__pgOverlay.showWarning(verdict);
        }
        config.triggerSend();
      } finally {
        scanning = false;
      }
    }

    document.addEventListener(
      "keydown",
      (e) => {
        if (scanning) return; // this is our own synthetic replay — let it pass
        const composer = config.getComposer();
        if (!composer) return;
        if (!config.isSendKeydown(e, composer)) return;
        handleSend(e, composer);
      },
      true,
    );

    if (config.getSendButton) {
      document.addEventListener(
        "click",
        (e) => {
          if (scanning) return;
          const btn = config.getSendButton();
          if (!btn || !(e.target === btn || btn.contains(e.target))) return;
          const composer = config.getComposer();
          if (!composer) return;
          handleSend(e, composer);
        },
        true,
      );
    }
  }

  window.__pgCreateGuard = createGuard;
  window.__pgCommon = { replaceContentEditable, setTextareaValue };
})();
