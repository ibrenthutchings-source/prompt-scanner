"""Read APIs for the CISO dashboard: events, drill-down, and live metrics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi.responses import PlainTextResponse

from app.db import get_session
from app.models import Action, Category, Finding, ScanEvent, Severity, Stage
from app.reporting import build_report, render_markdown
from app.schemas import AcknowledgeRequest, EventDetailOut, EventOut

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])


def _since(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


@router.get("/events", response_model=list[EventOut])
async def list_events(
    session: AsyncSession = Depends(get_session),
    hours: int = Query(24, ge=1, le=24 * 90),
    severity: list[Severity] | None = Query(None),
    action: list[Action] | None = Query(None),
    category: Category | None = Query(None),
    source: str | None = None,
    actor: str | None = None,
    department: str | None = None,
    unacknowledged_only: bool = False,
    escalated_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[ScanEvent]:
    stmt = select(ScanEvent).where(ScanEvent.created_at >= _since(hours))
    if severity:
        stmt = stmt.where(ScanEvent.severity.in_(severity))
    if action:
        stmt = stmt.where(ScanEvent.action.in_(action))
    if source:
        stmt = stmt.where(ScanEvent.source == source)
    if actor:
        stmt = stmt.where(ScanEvent.actor == actor)
    if department:
        stmt = stmt.where(ScanEvent.actor_department == department)
    if unacknowledged_only:
        stmt = stmt.where(ScanEvent.acknowledged_at.is_(None))
    if escalated_only:
        stmt = stmt.where(ScanEvent.retro_escalated.is_(True))
    if category:
        stmt = stmt.where(
            ScanEvent.id.in_(select(Finding.event_id).where(Finding.category == category))
        )
    stmt = stmt.order_by(ScanEvent.created_at.desc()).limit(limit).offset(offset)
    return list((await session.execute(stmt)).scalars())


@router.get("/events/{event_id}", response_model=EventDetailOut)
async def get_event(
    event_id: str, session: AsyncSession = Depends(get_session)
) -> ScanEvent:
    event = await session.get(ScanEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event


@router.post("/events/{event_id}/acknowledge", response_model=EventOut)
async def acknowledge(
    event_id: str,
    payload: AcknowledgeRequest,
    session: AsyncSession = Depends(get_session),
) -> ScanEvent:
    event = await session.get(ScanEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    event.acknowledged_by = payload.acknowledged_by
    event.acknowledged_at = datetime.now(timezone.utc)
    if payload.note:
        event.analyst_note = payload.note
    await session.commit()
    await session.refresh(event)
    return event


@router.get("/summary")
async def summary(
    session: AsyncSession = Depends(get_session),
    hours: int = Query(24, ge=1, le=24 * 90),
) -> dict:
    """Everything the landing view needs, in one round trip."""
    since = _since(hours)
    prior_since = since - timedelta(hours=hours)
    base = select(ScanEvent).where(ScanEvent.created_at >= since).subquery()

    total = (
        await session.execute(select(func.count()).select_from(base))
    ).scalar_one()
    prior_total = (
        await session.execute(
            select(func.count())
            .select_from(ScanEvent)
            .where(ScanEvent.created_at >= prior_since, ScanEvent.created_at < since)
        )
    ).scalar_one()

    by_action = dict(
        (
            await session.execute(
                select(ScanEvent.action, func.count())
                .where(ScanEvent.created_at >= since)
                .group_by(ScanEvent.action)
            )
        ).all()
    )
    by_severity = dict(
        (
            await session.execute(
                select(ScanEvent.severity, func.count())
                .where(ScanEvent.created_at >= since)
                .group_by(ScanEvent.severity)
            )
        ).all()
    )
    by_source = dict(
        (
            await session.execute(
                select(ScanEvent.source, func.count())
                .where(ScanEvent.created_at >= since)
                .group_by(ScanEvent.source)
                .order_by(func.count().desc())
                .limit(12)
            )
        ).all()
    )
    by_category = dict(
        (
            await session.execute(
                select(Finding.category, func.count(func.distinct(Finding.event_id)))
                .join(ScanEvent, ScanEvent.id == Finding.event_id)
                .where(ScanEvent.created_at >= since)
                .group_by(Finding.category)
            )
        ).all()
    )

    detector_rows = (
        await session.execute(
            select(
                Finding.detector,
                func.min(Finding.title).label("title"),
                func.max(Finding.score).label("score"),
                func.count().label("n"),
            )
            .join(ScanEvent, ScanEvent.id == Finding.event_id)
            .where(ScanEvent.created_at >= since)
            .group_by(Finding.detector)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    top_detectors = [
        {"detector": r.detector, "title": r.title, "count": r.n, "peak_score": r.score}
        for r in detector_rows
    ]

    # `blocked` counts only BLOCK actions; SQLAlchemy's case() keeps this
    # portable across SQLite and Postgres.
    blocked_expr = func.sum(case((ScanEvent.action == Action.BLOCK, 1), else_=0))
    actor_rows = (
        await session.execute(
            select(
                ScanEvent.actor,
                func.min(ScanEvent.actor_department).label("department"),
                func.count().label("events"),
                blocked_expr.label("blocked"),
                func.max(ScanEvent.risk_score).label("max_score"),
            )
            .where(ScanEvent.created_at >= since, ScanEvent.risk_score > 0)
            .group_by(ScanEvent.actor)
            .order_by(func.max(ScanEvent.risk_score).desc(), func.count().desc())
            .limit(10)
        )
    ).all()
    top_actors = [
        {
            "actor": r.actor or "unattributed",
            "department": r.department,
            "events": r.events,
            "blocked": r.blocked or 0,
            "max_score": r.max_score or 0,
        }
        for r in actor_rows
    ]

    open_criticals = (
        await session.execute(
            select(func.count())
            .select_from(ScanEvent)
            .where(
                ScanEvent.created_at >= since,
                ScanEvent.severity == Severity.CRITICAL,
                ScanEvent.acknowledged_at.is_(None),
            )
        )
    ).scalar_one()

    escalations = (
        await session.execute(
            select(func.count())
            .select_from(ScanEvent)
            .where(ScanEvent.created_at >= since, ScanEvent.retro_escalated.is_(True))
        )
    ).scalar_one()

    latency = (
        await session.execute(
            select(
                func.avg(ScanEvent.fast_gate_ms),
                func.max(ScanEvent.fast_gate_ms),
                func.avg(ScanEvent.council_ms),
                func.sum(ScanEvent.council_cost_usd),
            ).where(ScanEvent.created_at >= since)
        )
    ).one()

    return {
        "window_hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "events": total,
            "prior_events": prior_total,
            "change_pct": round(((total - prior_total) / prior_total) * 100, 1)
            if prior_total
            else None,
            "blocked": by_action.get(Action.BLOCK, 0),
            "redacted": by_action.get(Action.REDACT, 0),
            "warned": by_action.get(Action.WARN, 0),
            "allowed": by_action.get(Action.ALLOW, 0),
            "open_criticals": open_criticals,
            "retro_escalations": escalations,
        },
        "by_severity": {s.value: by_severity.get(s, 0) for s in Severity},
        "by_action": {a.value: by_action.get(a, 0) for a in Action},
        "by_category": {c.value: by_category.get(c, 0) for c in Category},
        "by_source": {k: v for k, v in by_source.items()},
        "top_detectors": top_detectors,
        "top_actors": top_actors,
        "performance": {
            "fast_gate_avg_ms": round(latency[0] or 0, 2),
            "fast_gate_max_ms": round(latency[1] or 0, 2),
            "council_avg_ms": round(latency[2] or 0, 1),
            "council_cost_usd": round(latency[3] or 0, 4),
        },
    }


@router.get("/timeseries")
async def timeseries(
    session: AsyncSession = Depends(get_session),
    hours: int = Query(24, ge=1, le=24 * 90),
    buckets: int = Query(24, ge=6, le=180),
) -> dict:
    """Event counts bucketed for the trend chart, split by action."""
    since = _since(hours)
    rows = (
        await session.execute(
            select(ScanEvent.created_at, ScanEvent.action, ScanEvent.severity).where(
                ScanEvent.created_at >= since
            )
        )
    ).all()

    span = timedelta(hours=hours) / buckets
    series = [
        {
            "t": (since + span * i).isoformat(),
            "allow": 0,
            "warn": 0,
            "redact": 0,
            "block": 0,
            "critical": 0,
        }
        for i in range(buckets)
    ]
    for created_at, action, severity in rows:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        idx = min(buckets - 1, int((created_at - since) / span))
        series[idx][action.value] += 1
        if severity is Severity.CRITICAL:
            series[idx]["critical"] += 1
    return {"since": since.isoformat(), "bucket_seconds": span.total_seconds(), "series": series}


@router.get("/regulations")
async def regulation_exposure(
    session: AsyncSession = Depends(get_session),
    hours: int = Query(168, ge=1, le=24 * 90),
) -> dict:
    """Which regulatory regimes the organisation is touching, and how often.

    This is the view a DPO or compliance lead actually opens: not "how many
    alerts" but "which obligations are in play".
    """
    since = _since(hours)
    rows = (
        await session.execute(
            select(Finding.regulations, Finding.severity, Finding.event_id)
            .join(ScanEvent, ScanEvent.id == Finding.event_id)
            .where(ScanEvent.created_at >= since)
        )
    ).all()

    tally: dict[str, dict] = {}
    for regulations, severity, event_id in rows:
        for reg in regulations or []:
            entry = tally.setdefault(
                reg, {"regulation": reg, "events": set(), "max_severity": Severity.NONE}
            )
            entry["events"].add(event_id)
            if severity.rank > entry["max_severity"].rank:
                entry["max_severity"] = severity

    items = sorted(
        (
            {
                "regulation": v["regulation"],
                "events": len(v["events"]),
                "max_severity": v["max_severity"].value,
            }
            for v in tally.values()
        ),
        key=lambda x: -x["events"],
    )
    return {"window_hours": hours, "regulations": items}


@router.get("/report")
async def report(
    session: AsyncSession = Depends(get_session),
    hours: int = Query(24, ge=1, le=24 * 90),
    fmt: str = Query("json", pattern="^(json|markdown)$"),
):
    """Periodic digest for scheduled delivery (cron, email, Slack bot)."""
    data = await build_report(session, hours=hours)
    if fmt == "markdown":
        return PlainTextResponse(render_markdown(data), media_type="text/markdown")
    return data


@router.get("/council/{event_id}")
async def council_detail(
    event_id: str, session: AsyncSession = Depends(get_session)
) -> dict:
    """Full council transcript for one event — the deliberation, not just the verdict."""
    event = await session.get(ScanEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return {
        "event_id": event.id,
        "status": event.council_status,
        "summary": event.council_summary,
        "elapsed_ms": event.council_ms,
        "cost_usd": event.council_cost_usd,
        "votes": [
            {
                "agent": v.agent,
                "model": v.model,
                "severity": v.severity.value,
                "confidence": v.confidence,
                "rationale": v.rationale,
                "findings": v.payload.get("findings", v.payload.get("confirmed_findings", [])),
                "latency_ms": v.latency_ms,
                "tokens": {
                    "input": v.input_tokens,
                    "output": v.output_tokens,
                    "cache_read": v.cache_read_tokens,
                },
                "error": v.error,
            }
            for v in sorted(event.votes, key=lambda v: (v.agent == "adjudicator", v.agent))
        ],
        "council_findings": [
            {
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "detail": f.detail,
                "regulations": f.regulations,
            }
            for f in event.findings
            if f.stage is Stage.COUNCIL
        ],
    }
