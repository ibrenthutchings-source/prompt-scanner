# Prompt Gateway — Dashboard

React + Vite + TypeScript CISO-facing dashboard for the Prompt Scanner gateway.
See the [repo root README](../README.md) for the overall architecture.

## What's here

- **Real-time feed** — WebSocket connection to `/v1/live` on the gateway,
  with automatic reconnect/backoff and history backfill on open.
- **Summary view** — stat tiles, an activity-by-outcome chart, findings by
  category, regulatory exposure, top detectors, and highest-risk actors —
  all driven by `/v1/dashboard/summary`, `/timeseries`, and `/regulations`.
- **Drill-down** — click any event for the full finding list plus, when the
  AI council reviewed it, the complete per-agent deliberation transcript.
- **Digest export** — a link to `/v1/dashboard/report?fmt=markdown` for a
  periodic (e.g. daily/weekly) plain-text security digest suitable for
  cron/Slack delivery.

Colors follow a validated, colorblind-safe palette (see the project's
`dataviz` design reference) — status colors (good/warning/serious/critical)
are fixed and always paired with an icon + label, never hue alone; category
colors are assigned in a fixed order. Both light and dark themes are
implemented; the theme selector in the header overrides the OS preference.

## Development

```bash
npm install
npm run dev   # http://localhost:5173 — proxies /v1/* to http://127.0.0.1:8000
```

Point `vite.config.ts`'s proxy target at a different gateway host if it's not
running on the default `127.0.0.1:8000`.

## Build

```bash
npm run build   # outputs to dist/
```

The Docker image (`Dockerfile`) builds this and serves it via nginx, which
also reverse-proxies `/v1/*` (including the WebSocket) to the `gateway`
service — see `nginx.conf` and the root `docker-compose.yml`.
