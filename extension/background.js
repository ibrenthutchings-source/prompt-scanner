/**
 * Service worker: the only place that talks to the gateway.
 *
 * Content scripts run inside the target page's process and are subject to
 * that page's CSP — claude.ai / chatgpt.com / gemini.google.com all ship
 * connect-src allowlists that would silently block a fetch to a third-party
 * gateway origin. The background worker has none of that; it fetches on the
 * extension's own network context, gated by host_permissions instead of the
 * page's policy. Content scripts message this file rather than fetching
 * directly — that's the whole reason this file exists.
 */

const DEFAULT_SETTINGS = {
  gatewayUrl: "http://127.0.0.1:8000",
  actor: "",
  department: "",
  waitForCouncil: false,
  enabled: true,
};

async function getSettings() {
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

async function scanPrompt(payload) {
  const settings = await getSettings();
  if (!settings.enabled) {
    return { ok: true, skipped: true };
  }

  const body = {
    text: payload.text,
    source: "extension",
    client_app: payload.site,
    provider: payload.provider || null,
    actor: settings.actor || null,
    actor_department: settings.department || null,
    session_id: payload.sessionId || null,
    attachments: payload.attachments || [],
    wait_for_council: settings.waitForCouncil,
    metadata: { url: payload.url },
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  try {
    const res = await fetch(`${settings.gatewayUrl.replace(/\/$/, "")}/v1/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: `Gateway returned ${res.status}: ${text.slice(0, 300)}` };
    }
    const verdict = await res.json();
    return { ok: true, verdict };
  } catch (err) {
    return { ok: false, error: `Could not reach gateway at ${settings.gatewayUrl}: ${err}` };
  } finally {
    clearTimeout(timeout);
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_PROMPT") {
    scanPrompt(message.payload).then(sendResponse);
    return true; // keep the message channel open for the async response
  }
  if (message?.type === "GET_SETTINGS") {
    getSettings().then(sendResponse);
    return true;
  }
  return false;
});

// First install: seed defaults so the options page has something to show.
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.sync.get(null);
  if (Object.keys(current).length === 0) {
    await chrome.storage.sync.set(DEFAULT_SETTINGS);
  }
});
