"""Periodic reports: a plain-text/markdown digest a CISO team can read without
opening the dashboard, and JSON for piping into a SIEM or scheduler.

Exposed via GET /v1/dashboard/report and intended to be hit by cron / the
`schedule` skill / a scheduled deployment on whatever cadence the org wants
(daily is the common case).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Action, Finding, ScanEvent, Severity


async def build_report(session: AsyncSession, hours: int = 24) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = list(
        (
            await session.execute(
                select(ScanEvent).where(ScanEvent.created_at >= since)
            )
        ).scalars()
    )

    by_severity = {s: 0 for s in Severity}
    by_action = {a: 0 for a in Action}
    for e in events:
        by_severity[e.severity] += 1
        by_action[e.action] += 1

    criticals = sorted(
        (e for e in events if e.severity is Severity.CRITICAL),
        key=lambda e: e.created_at,
        reverse=True,
    )
    escalations = [e for e in events if e.retro_escalated]

    reg_rows = (
        await session.execute(
            select(Finding.regulations)
            .join(ScanEvent, ScanEvent.id == Finding.event_id)
            .where(ScanEvent.created_at >= since)
        )
    ).all()
    reg_counts: dict[str, int] = {}
    for (regs,) in reg_rows:
        for r in regs or []:
            reg_counts[r] = reg_counts.get(r, 0) + 1

    cost = sum(e.council_cost_usd for e in events)

    return {
        "period": {
            "since": since.isoformat(),
            "until": datetime.now(timezone.utc).isoformat(),
            "hours": hours,
        },
        "totals": {
            "events_scanned": len(events),
            "blocked": by_action[Action.BLOCK],
            "redacted": by_action[Action.REDACT],
            "warned": by_action[Action.WARN],
            "critical_findings": by_severity[Severity.CRITICAL],
            "high_findings": by_severity[Severity.HIGH],
            "retroactive_escalations": len(escalations),
            "council_spend_usd": round(cost, 2),
        },
        "top_regulations": sorted(
            [{"regulation": k, "events": v} for k, v in reg_counts.items()],
            key=lambda x: -x["events"],
        )[:10],
        "critical_events": [
            {
                "event_id": e.id,
                "occurred_at": e.created_at.isoformat(),
                "actor": e.actor,
                "department": e.actor_department,
                "action": e.action.value,
                "reason": e.action_reason,
                "acknowledged": e.acknowledged_at is not None,
            }
            for e in criticals[:25]
        ],
        "unacknowledged_criticals": sum(
            1 for e in criticals if e.acknowledged_at is None
        ),
    }


def render_markdown(report: dict) -> str:
    t = report["totals"]
    period = report["period"]
    lines = [
        f"# Prompt Gateway Security Digest — {period['hours']}h",
        f"_{period['since']} → {period['until']}_",
        "",
        "## Summary",
        f"- Prompts scanned: **{t['events_scanned']}**",
        f"- Blocked: **{t['blocked']}**  ·  Redacted: **{t['redacted']}**  ·  "
        f"Warned: **{t['warned']}**",
        f"- Critical findings: **{t['critical_findings']}**  "
        f"({report['unacknowledged_criticals']} unacknowledged)",
        f"- Retroactive escalations (council caught what the fast gate missed): "
        f"**{t['retroactive_escalations']}**",
        f"- Council spend: **${t['council_spend_usd']}**",
        "",
    ]

    if report["top_regulations"]:
        lines.append("## Regulatory exposure")
        for r in report["top_regulations"]:
            lines.append(f"- {r['regulation']}: {r['events']} events")
        lines.append("")

    if report["critical_events"]:
        lines.append("## Critical events")
        lines.append("| Event | When | Actor | Dept | Action | Ack |")
        lines.append("|---|---|---|---|---|---|")
        for e in report["critical_events"]:
            lines.append(
                f"| {e['event_id'][:8]} | {e['occurred_at']} | {e['actor'] or '—'} | "
                f"{e['department'] or '—'} | {e['action']} | "
                f"{'✓' if e['acknowledged'] else '—'} |"
            )
    else:
        lines.append("## Critical events")
        lines.append("None in this period.")

    return "\n".join(lines)
