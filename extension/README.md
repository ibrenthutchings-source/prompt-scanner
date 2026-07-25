# Prompt Gateway Scanner — browser extension

Covers the gap the reverse proxy can't: consumer web chat UIs (chatgpt.com,
claude.ai, gemini.google.com) where there's no API base URL to point at the
gateway. This extension intercepts the composer's send action directly in the
page, scans the text via the gateway's `/v1/scan` endpoint, and blocks/warns/
redacts before anything reaches the vendor's servers.

## Install (unpacked, for internal distribution)

1. `chrome://extensions` → enable Developer Mode → **Load unpacked** → select
   this `extension/` folder.
2. Click the extension icon → **Settings** → set **Gateway URL** to your
   gateway's address (defaults to `http://127.0.0.1:8000` for local dev).
   Changing it to a non-localhost origin will prompt for a one-time
   permission grant for that specific host — this is expected and is what
   lets the extension reach your gateway without a broad `<all_urls>` grant.
3. Optionally set your identifier/department (shown to analysts on the
   dashboard) and whether to wait for the full AI council before sending.

For a managed rollout, package this as a private Chrome extension pushed via
your MDM/Chrome Enterprise policy so users don't need Developer Mode.

## How it works

- `background.js` is the only piece that talks to the gateway — content
  scripts message it rather than fetching directly, because the target
  sites' own Content-Security-Policy would otherwise block a cross-origin
  fetch issued from inside the page.
- Each site's content script (`content/chatgpt.js`, `content/claude.js`,
  `content/gemini.js`) hooks the composer's Enter-to-send and send-button
  click at the document capture phase, so it sees the action before the
  site's own handlers do.
- On a **block** verdict, the send never happens — the user sees a modal
  explaining why, with the specific findings, and there's no bypass.
- On a **redact** verdict, the composer text is replaced with masked
  content and the user is prompted to review and send again (no
  auto-resend — the user should see what changed before it goes out).
- On a **warn** verdict, a dismissible toast appears and the message sends
  as normal.
- If the gateway is unreachable, the extension **fails open** — the prompt
  sends and a toast says so. Blocking someone's work because a security
  appliance is down is its own kind of incident; the outage itself will
  surface through the gateway's own health checks and alerting once it's
  monitored centrally, not through the end user.

## A note on selectors

The composer/send-button selectors in each `content/*.js` file are the
authors' best current read of each site's DOM. All three sites are actively
developed SPAs and *will* change their markup eventually — when a hook stops
firing, open devtools on the composer, find the new attribute, and update the
`SELECTORS` object at the top of the relevant file. The interception and
verdict-handling logic in `content/common.js` never needs to change.

## Attachments

Images and PDFs pasted into these web UIs are not currently intercepted by
this extension — only the DOM text composer is hooked. If your organization
needs attachment coverage on the consumer web UIs specifically (as opposed to
the API/SDK traffic the reverse proxy already covers, which does inspect
attachments — see the gateway's own README), that requires hooking each
site's file-upload/paste handlers per site, which is a larger follow-up.
