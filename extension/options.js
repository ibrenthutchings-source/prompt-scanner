const DEFAULTS = {
  gatewayUrl: "http://127.0.0.1:8000",
  actor: "",
  department: "",
  waitForCouncil: false,
  enabled: true,
};

const els = {
  enabled: document.getElementById("enabled"),
  gatewayUrl: document.getElementById("gatewayUrl"),
  actor: document.getElementById("actor"),
  department: document.getElementById("department"),
  waitForCouncil: document.getElementById("waitForCouncil"),
  save: document.getElementById("save"),
  status: document.getElementById("status"),
};

async function load() {
  const settings = await chrome.storage.sync.get(DEFAULTS);
  els.enabled.checked = settings.enabled;
  els.gatewayUrl.value = settings.gatewayUrl;
  els.actor.value = settings.actor;
  els.department.value = settings.department;
  els.waitForCouncil.checked = settings.waitForCouncil;
}

function originPattern(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

async function save() {
  els.status.textContent = "";
  const gatewayUrl = els.gatewayUrl.value.trim().replace(/\/$/, "");
  if (!gatewayUrl) {
    els.status.textContent = "Gateway URL is required.";
    els.status.style.color = "#d03b3b";
    return;
  }

  const pattern = originPattern(gatewayUrl);
  if (!pattern) {
    els.status.textContent = "That doesn't look like a valid URL.";
    els.status.style.color = "#d03b3b";
    return;
  }

  // A custom (non-localhost) gateway origin needs its own permission grant —
  // the manifest only ships static permission for the local dev default.
  // Requesting it here, at save time, means the user sees exactly what
  // they're granting and why, instead of a silent broad-host request at
  // install time.
  const alreadyGranted = await chrome.permissions.contains({ origins: [pattern] });
  if (!alreadyGranted) {
    const granted = await chrome.permissions.request({ origins: [pattern] });
    if (!granted) {
      els.status.textContent = `Permission for ${pattern} was not granted — the extension cannot reach that gateway.`;
      els.status.style.color = "#d03b3b";
      return;
    }
  }

  await chrome.storage.sync.set({
    gatewayUrl,
    actor: els.actor.value.trim(),
    department: els.department.value.trim(),
    waitForCouncil: els.waitForCouncil.checked,
    enabled: els.enabled.checked,
  });

  els.status.textContent = "Saved.";
  els.status.style.color = "#0ca30c";
  setTimeout(() => (els.status.textContent = ""), 2500);
}

els.save.addEventListener("click", save);
load();
