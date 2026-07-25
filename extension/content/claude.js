/**
 * claude.ai
 *
 * The composer is a contenteditable ProseMirror region without a consistently
 * documented stable id, so this leans on aria-label plus a generic
 * contenteditable-inside-the-composer-form fallback. If Anthropic changes the
 * DOM and this stops matching, update SELECTORS — see chatgpt.js for the same
 * note.
 */
(function () {
  const SELECTORS = {
    composer: [
      'div[contenteditable="true"][aria-label*="prompt" i]',
      'div[contenteditable="true"][aria-label*="Claude" i]',
      'div.ProseMirror[contenteditable="true"]',
      'fieldset div[contenteditable="true"]',
    ],
    sendButton: [
      'button[aria-label="Send message" i]',
      'button[aria-label*="Send" i]',
    ],
  };

  function firstMatch(selectors) {
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  window.__pgCreateGuard({
    siteName: "claude",
    provider: "anthropic",
    getComposer: () => firstMatch(SELECTORS.composer),
    getSendButton: () => firstMatch(SELECTORS.sendButton),
    isSendKeydown: (e, composer) => {
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return false;
      return composer.contains(document.activeElement) || document.activeElement === composer;
    },
    triggerSend: () => {
      const btn = firstMatch(SELECTORS.sendButton);
      if (btn && !btn.disabled && btn.getAttribute("aria-disabled") !== "true") {
        btn.click();
      }
    },
  });
})();
