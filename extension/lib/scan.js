/**
 * Thin wrapper around chrome.runtime messaging to the background worker,
 * which does the actual fetch (see background.js for why).
 */
(function () {
  if (window.__pgScan) return;

  function scanPrompt(payload) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "SCAN_PROMPT", payload }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }
        resolve(response || { ok: false, error: "no response from background worker" });
      });
    });
  }

  window.__pgScan = { scanPrompt };
})();
