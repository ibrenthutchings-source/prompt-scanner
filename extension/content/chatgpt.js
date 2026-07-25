/**
 * chatgpt.com / chat.openai.com
 *
 * Selectors are best-known-current as of this writing. ChatGPT's composer is
 * a ProseMirror contenteditable region; the send button carries a stable
 * data-testid across recent redesigns. If OpenAI ships a redesign and this
 * stops firing, open devtools on the composer, confirm the new selector, and
 * update SELECTORS below — the interception logic in common.js does not
 * change.
 */
(function () {
  const SELECTORS = {
    composer: ['#prompt-textarea', 'div[contenteditable="true"][id*="prompt"]', 'form div[contenteditable="true"]'],
    sendButton: ['[data-testid="send-button"]', 'button[aria-label="Send prompt"]'],
  };

  function firstMatch(selectors) {
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  window.__pgCreateGuard({
    siteName: "chatgpt",
    provider: "openai",
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
