"""Outbound alerting.

Fire-and-forget by design: an unreachable SIEM must never turn into a failed
prompt. Delivery failures are logged and dropped, because the durable record is
already in the database and the dashboard reads from there.
"""

from __future__ import annotations

import logging

import httpx

from app.config import get_settings
from app.models import Action, ScanEvent, Severity

log = logging.getLogger(__name__)

_SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}


def _should_alert(event: ScanEvent) -> bool:
    settings = get_settings()
    if not settings.webhook_url:
        return False
    threshold = Severity(settings.webhook_min_severity)
    return _SEV_ORDER[event.severity] >= _SEV_ORDER[threshold]


def build_payload(event: ScanEvent, *, escalation: bool = False) -> dict:
    """Shaped for generic webhook consumers (Slack-compatible `text` plus the
    structured body a SIEM will actually parse)."""
    top = sorted(event.findings, key=lambda f: -_SEV_ORDER[f.severity])[:5]
    regulations = sorted({r for f in event.findings for r in (f.regulations or [])})
    headline = (
        f"{'ESCALATION — ' if escalation else ''}"
        f"{event.severity.value.upper()} · {event.action.value} · "
        f"{event.actor or 'unknown actor'} → {event.provider or event.source}"
    )
    return {
        "text": headline,
        "event_id": event.id,
        "escalation": escalation,
        "occurred_at": event.created_at.isoformat(),
        "severity": event.severity.value,
        "action": event.action.value,
        "risk_score": event.risk_score,
        "actor": event.actor,
        "department": event.actor_department,
        "source": event.source,
        "client_app": event.client_app,
        "provider": event.provider,
        "model": event.model,
        "reason": event.action_reason,
        "council_status": event.council_status,
        "council_summary": event.council_summary,
        "regulations": regulations,
        "findings": [
            {
                "category": f.category.value,
                "detector": f.detector,
                "severity": f.severity.value,
                "title": f.title,
                "evidence": f.evidence,
            }
            for f in top
        ],
    }


async def dispatch(event: ScanEvent, *, escalation: bool = False) -> None:
    if not _should_alert(event):
        return
    settings = get_settings()
    payload = build_payload(event, escalation=escalation)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(settings.webhook_url, json=payload)
            if resp.status_code >= 400:
                log.warning("alert webhook returned %s for %s", resp.status_code, event.id)
    except Exception as exc:
        log.warning("alert webhook failed for %s: %s", event.id, exc)


def action_escalated(before: Action, after: Action) -> bool:
    rank = {Action.ALLOW: 0, Action.WARN: 1, Action.REDACT: 2, Action.BLOCK: 3}
    return rank[after] > rank[before]
