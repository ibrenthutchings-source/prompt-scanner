async function main() {
  const settings = await new Promise((resolve) =>
    chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, resolve),
  );

  const enabledDot = document.getElementById("enabledDot");
  const enabledLabel = document.getElementById("enabledLabel");
  const gatewayDot = document.getElementById("gatewayDot");
  const gatewayLabel = document.getElementById("gatewayLabel");
  const dashboardLink = document.getElementById("openDashboard");

  if (settings.enabled) {
    enabledDot.className = "dot ok";
    enabledLabel.textContent = "Scanning is on";
  } else {
    enabledDot.className = "dot off";
    enabledLabel.textContent = "Scanning is off";
  }

  dashboardLink.href = settings.gatewayUrl;

  try {
    const res = await fetch(`${settings.gatewayUrl.replace(/\/$/, "")}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      gatewayDot.className = "dot ok";
      gatewayLabel.textContent = "Gateway reachable";
    } else {
      gatewayDot.className = "dot bad";
      gatewayLabel.textContent = `Gateway returned ${res.status}`;
    }
  } catch (err) {
    gatewayDot.className = "dot bad";
    gatewayLabel.textContent = "Gateway unreachable";
  }

  document.getElementById("openOptions").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

main();
