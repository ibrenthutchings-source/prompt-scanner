# Prompt Scanner

An API gateway / proxy that audits outbound LLM prompts — from any client,
API-based or browser-based — for PII, PHI, IP, secrets, and regulatory
exposure (GDPR, the EU AI Act, HIPAA, PCI-DSS and others), before the prompt
reaches OpenAI, Anthropic, or any other model provider. Risk is judged by a
council of specialist AI agents plus deterministic detectors, enforcement is
policy-driven (allow / warn / redact / block), and everything lands on a
real-time CISO dashboard.

```
┌─────────────┐   ┌──────────────┐   ┌───────────────────────────────┐
│  SDK / IDE  │──▶│              │   │  Stage 1 — fast gate (~1ms)   │
│  (Cursor,   │   │   Gateway    │──▶│  regex + checksums + context  │──▶ policy ──▶ allow / warn /
│  LangChain…)│   │   (FastAPI)  │   │  rules, inline on every req   │            redact / block
└─────────────┘   │              │   └───────────────────────────────┘
┌─────────────┐   │  /anthropic  │              │ score ≥ threshold, or an
│  Browser    │──▶│  /openai     │              │ attachment needing vision
│  extension  │   │  /v1/scan    │              ▼
│ (chatgpt.com│   │              │   ┌───────────────────────────────┐
│  claude.ai, │   └──────┬───────┘   │  Stage 2 — the council (async)│
│  gemini)    │          │           │  5 specialist agents (parallel)│
└─────────────┘          │           │  → 1 adjudicator → verdict     │
                          │           └───────────────────────────────┘
                          ▼
                 ┌──────────────────┐        ┌───────────────────┐
                 │  Postgres/SQLite  │◀──────▶│  React dashboard  │
                 │  events, findings,│  REST  │  live feed, drill- │
                 │  council votes    │  + WS  │  down, digests     │
                 └──────────────────┘        └───────────────────┘
```

## Why two stages

Prompt latency and prompt *judgment* pull in opposite directions. Deterministic
detectors (regex, Luhn/IBAN/NPI checksums, entropy-based secret detection,
context-gated keyword rules) run in under a millisecond and can block outright
— a live AWS key or a validated SSN never needs an LLM's opinion. But they miss
what has no fixed pattern: whether a described use case is an EU AI Act Article
5 prohibited practice, whether a code paste is proprietary or boilerplate,
whether a screenshot contains a patient chart. That's the council's job, and it
runs off the request path so five Opus calls never cost the user typing
latency — the prompt is already in flight (or already blocked by the fast
gate) by the time the council weighs in. If the council escalates *after* a
prompt was allowed, that's recorded as a retroactive escalation and raised
loudly on the dashboard rather than silently logged.

## Components

| Path | What it is |
|---|---|
| `gateway/` | FastAPI backend: detectors, council, policy engine, reverse proxy, dashboard API, WebSocket live feed |
| `dashboard/` | React + Vite CISO dashboard: real-time feed, stat tiles, category/regulation breakdowns, drill-down with full council transcript |
| `extension/` | MV3 browser extension for chatgpt.com / claude.ai / gemini.google.com — the web UIs an API proxy can't reach |
| `docker-compose.yml` | Postgres + gateway + dashboard, wired together for a full local/staging stack |

Each has its own README with the details specific to it.

## Quickstart (local dev, no Docker)

```bash
# 1. Gateway
cd gateway
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -e .
cp .env.example ../.env    # edit as needed; ANTHROPIC_API_KEY via env or `ant auth login`
uvicorn app.main:app --reload --port 8000

# 2. Dashboard (separate terminal)
cd dashboard
npm install
npm run dev    # http://localhost:5173, proxies /v1 to :8000 automatically

# 3. Point a client at the gateway instead of the provider directly
export ANTHROPIC_BASE_URL=http://localhost:8000/anthropic
# or for OpenAI-compatible clients:
export OPENAI_BASE_URL=http://localhost:8000/openai/v1
```

Then load `extension/` as an unpacked extension in Chrome (`chrome://extensions`
→ Developer Mode → Load unpacked) to cover the consumer web UIs.

## Quickstart (Docker Compose)

```bash
cp gateway/.env.example .env   # edit; set ANTHROPIC_API_KEY
docker compose up --build
# dashboard: http://localhost:8080
# gateway:   http://localhost:8000
```

## Enforcement model

Every prompt gets a severity (`none`→`critical`) and an action:

| Action | Meaning |
|---|---|
| `allow` | No meaningful risk; prompt goes through unchanged |
| `warn` | Real but lower-grade exposure; allowed, logged, employee sees why |
| `redact` | Sensitive spans are masked in place before the request continues — the API caller gets this transparently; no error, no blocked work |
| `block` | Never transmitted. The API caller gets a 403 shaped like the destination provider's own error envelope (so it renders natively in the Anthropic/OpenAI SDKs, Cursor, curl, etc.); the browser extension shows a modal that cannot be clicked through |

The full ladder — which detectors trigger which action, which departments get
narrower exemptions, the exact user-facing copy — lives in
[`gateway/app/policy/policy.yaml`](gateway/app/policy/policy.yaml) and reloads
without a restart via `POST /v1/admin/policy/reload`. Nothing about the
enforcement logic is hardcoded in Python; that file is the thing a security
team actually edits.

## What gets scanned

- **Text** — every request/response content block across Anthropic Messages,
  OpenAI Chat Completions, and OpenAI Responses shapes, including tool
  results and multi-turn history (only the *new* turns are re-evaluated each
  round, so a long conversation doesn't re-flag turn 1 on every message).
- **Images and PDFs** — recognized attachments are forwarded to the council
  for a native vision read (Claude reads images/PDFs directly); anything the
  council can't see (unsupported type, an unresolved Files API reference, or
  the council being disabled) is flagged as an explicit *unscanned attachment*
  finding rather than silently passing through unexamined.
- **Secrets** — AWS/GitHub/Anthropic/OpenAI/Google/Slack/Stripe credentials,
  private key blocks, JWTs, DB connection strings, and a generic high-entropy
  `key=value` catch-all, all inline in the sub-millisecond fast gate.

## The council

Five specialist agents (Privacy Counsel, Clinical Compliance, IP & Trade
Secret Custodian, AI Act & Algorithmic Governance, Adversarial Reviewer) review
a flagged prompt in parallel, then an Adjudicator reconciles their opinions —
including overturning findings the Adversarial Reviewer identifies as false
positives — into one verdict with a rationale, a false-positive-risk rating,
and specific regulatory citations. See
[`gateway/app/council/agents.py`](gateway/app/council/agents.py) for the full
charters. All five specialists share one cached system-prompt prefix (see
`gateway/app/council/runner.py`) so a review costs one cache write instead of
five.
