/**
 * gemini.google.com
 *
 * The composer is a Quill-based contenteditable (`.ql-editor`) inside a
 * custom element. Send is normally triggered by Enter or a send button with
 * aria-label "Send message". As with the other two sites, update SELECTORS
 * if Google reworks the composer — see chatgpt.js for the same note.
 */
(function () {
  const SELECTORS = {
    composer: [
      "rich-textarea .ql-editor",
      'div[contenteditable="true"].ql-editor',
      '[aria-label="Enter a prompt here"]',
    ],
    sendButton: [
      'button[aria-label="Send message"]',
      "button.send-button",
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
    siteName: "gemini",
    provider: "google",
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
