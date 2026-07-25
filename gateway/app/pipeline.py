"""The two-stage evaluation pipeline.

    prompt ──> fast gate (inline, ~1ms) ──> policy ──> verdict ──> caller
                     │
                     └──> council (background, seconds) ──> policy again
                                                              │
                                    escalation? ──> alert + dashboard update

Stage 1 owns the request path and must be fast enough that nobody notices it.
Stage 2 owns judgement and runs behind the response, so a five-model review
never costs the user latency. When the council escalates after the fact, the
event is marked `retro_escalated` and the session is surfaced to analysts —
the prompt already went, so the honest thing is to raise it loudly rather than
pretend it was caught in time.

Callers that need certainty before transmitting (the browser extension on a
high-scoring prompt) can opt into `wait_for_council`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import alerts, redact
from app.config import get_settings
from app.council import get_council
from app.council.runner import CouncilResult
from app.db import session_scope
from app.detect import fastgate
from app.events import bus
from app.models import Action, Category, CouncilVote, Finding, ScanEvent, Severity, Stage
from app.policy.engine import Decision, get_policy
from app.schemas import AttachmentInfo, DetectionHit, EventOut, PromptContext, Verdict

log = logging.getLogger(__name__)

_background: set[asyncio.Task] = set()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _max_severity(hits: list[DetectionHit], floor: Severity) -> Severity:
    best = floor
    for hit in hits:
        if hit.severity.rank > best.rank:
            best = hit.severity
    return best


async def evaluate(ctx: PromptContext, session: AsyncSession) -> Verdict:
    """Stage 1. Always returns; never raises on detector or policy failure."""
    settings = get_settings()

    gate = fastgate.run(ctx.text, evidence_chars=settings.evidence_context_chars)
    gate.hits.extend(_attachment_hits(ctx.attachments))
    gate.score = fastgate.score_hits(gate.hits)
    gate.severity = _max_severity(gate.hits, fastgate.severity_for_score(gate.score))

    policy = get_policy()
    decision = policy.evaluate(ctx, gate.hits, gate.score, gate.severity)

    # Redaction only helps when there are spans to mask. Otherwise escalate to
    # warn rather than silently allowing an unmasked prompt through.
    redacted_text = None
    if decision.action is Action.REDACT:
        if redact.redactable(gate.hits):
            redacted_text, masked = redact.redact(ctx.text, gate.hits)
            if masked == 0:
                decision = _downgrade_to_warn(decision)
                redacted_text = None
        else:
            decision = _downgrade_to_warn(decision)

    event = ScanEvent(
        source=ctx.source,
        client_app=ctx.client_app,
        provider=ctx.provider,
        model=ctx.model,
        actor=ctx.actor,
        actor_department=ctx.actor_department,
        session_id=ctx.session_id,
        src_ip=ctx.src_ip,
        prompt_chars=len(ctx.text),
        prompt_sha256=_sha256(ctx.text),
        raw_prompt=ctx.text if settings.store_raw_prompts else None,
        risk_score=gate.score,
        severity=gate.severity,
        action=decision.action,
        action_reason=decision.reason,
        council_status="pending" if _council_wanted(gate.score, ctx.attachments) else "skipped",
        fast_gate_ms=gate.elapsed_ms,
    )
    session.add(event)
    await session.flush()

    for hit in gate.hits:
        session.add(_finding_row(event.id, hit))
    await session.commit()
    await session.refresh(event)

    message = decision.message.replace("{event_id}", event.id)
    await _broadcast(event, "event.created")
    _fire(alerts.dispatch(event))

    if event.council_status == "pending":
        _spawn(_council_pass(event.id, ctx, gate.hits))

    return Verdict(
        event_id=event.id,
        action=decision.action,
        severity=gate.severity,
        risk_score=gate.score,
        reason=decision.reason,
        message=message,
        hits=gate.hits,
        redacted_text=redacted_text,
        council_status=event.council_status,
        fast_gate_ms=gate.elapsed_ms,
    )


def _downgrade_to_warn(decision: Decision) -> Decision:
    return Decision(
        action=Action.WARN,
        reason=f"{decision.reason}+nothing_maskable",
        message=(
            "This prompt was flagged but the findings have no maskable span "
            "(they concern the request as a whole, not a specific value). "
            "It was allowed and logged for review as event {event_id}."
        ),
        rule=decision.rule,
        exemption=decision.exemption,
        matched_hits=decision.matched_hits,
    )


def _council_wanted(score: int, attachments: list[AttachmentInfo]) -> bool:
    """Score-based trigger, plus an unconditional trigger for inspectable
    attachments — pattern matching cannot see into an image or PDF at all, so
    the score threshold (tuned for text) must not gate the only mechanism
    that *can* look."""
    settings = get_settings()
    council = get_council()
    if not council.available:
        return False
    if any(a.inspectable for a in attachments):
        return True
    return score >= settings.council_min_score


def _attachment_hits(attachments: list[AttachmentInfo]) -> list[DetectionHit]:
    """Attachments are opaque to every fast-gate detector. Say so, rather than
    letting an image or PDF pass through with no record at all. Severity stays
    low here — it is a visibility note, not a verdict; the council (if
    available and triggered) makes the actual call after looking at the
    content, and its findings supersede this placeholder."""
    council_can_look = get_council().available
    hits = []
    for a in attachments:
        if a.inspectable and council_can_look:
            hits.append(
                DetectionHit(
                    stage=Stage.FAST_GATE,
                    category=Category.IP,
                    detector="attachment_pending_review",
                    severity=Severity.LOW,
                    confidence=1.0,
                    score=3,
                    title=f"{a.kind.title()} attachment ({a.media_type}, ~{a.size_bytes:,} bytes) "
                    "queued for council vision review",
                    detail="Pattern-based detectors cannot inspect binary content; this "
                    "attachment is routed to the council for a visual read.",
                )
            )
        else:
            why = (
                "the AI review council is not configured on this gateway"
                if a.inspectable and not council_can_look
                else "its type or delivery method (e.g. a Files API reference, or an "
                "unsupported media type) is not one the council can read"
            )
            hits.append(
                DetectionHit(
                    stage=Stage.FAST_GATE,
                    category=Category.IP,
                    detector="attachment_unscanned",
                    severity=Severity.MEDIUM,
                    confidence=1.0,
                    score=12,
                    title=f"Unscanned {a.kind} attachment"
                    + (f" ({a.media_type})" if a.media_type else ""),
                    detail=f"This attachment was not inspected because {why}. Neither the "
                    "pattern detectors nor the council could see its content before it "
                    "left the perimeter — treat this as an unknown-content disclosure.",
                    regulations=["GDPR Art. 5(1)(f) (integrity and confidentiality)"],
                )
            )
    return hits


def _finding_row(event_id: str, hit: DetectionHit) -> Finding:
    return Finding(
        event_id=event_id,
        stage=hit.stage,
        category=hit.category,
        detector=hit.detector,
        severity=hit.severity,
        confidence=hit.confidence,
        score=hit.score,
        title=hit.title,
        detail=hit.detail,
        evidence=hit.evidence,
        start=hit.start,
        end=hit.end,
        regulations=hit.regulations,
    )


# ---------------------------------------------------------------------------
# Stage 2
# ---------------------------------------------------------------------------


async def review_now(ctx: PromptContext, fast_hits: list[DetectionHit]) -> CouncilResult:
    """Synchronous council pass for callers that opted into waiting."""
    return await get_council().review(ctx, fast_hits)


async def _council_pass(event_id: str, ctx: PromptContext, fast_hits: list[DetectionHit]) -> None:
    try:
        result = await get_council().review(ctx, fast_hits)
    except Exception as exc:  # never let a background task die silently
        log.exception("council pass crashed for %s", event_id)
        result = CouncilResult(status="failed", summary=f"{type(exc).__name__}: {exc}")

    async with session_scope() as session:
        event = await session.get(ScanEvent, event_id)
        if event is None:
            return
        await apply_council(session, event, ctx, fast_hits, result)


async def apply_council(
    session: AsyncSession,
    event: ScanEvent,
    ctx: PromptContext,
    fast_hits: list[DetectionHit],
    result: CouncilResult,
) -> Decision:
    """Merge a council result into an existing event and re-run policy.

    Returns the post-council decision so synchronous callers can surface its
    message; the background path ignores the return value.
    """
    prior_action = event.action

    for vote in result.votes:
        session.add(
            CouncilVote(
                event_id=event.id,
                agent=vote.agent,
                model=vote.model,
                severity=vote.severity,
                confidence=vote.confidence,
                rationale=vote.rationale,
                payload=vote.payload,
                latency_ms=vote.latency_ms,
                input_tokens=vote.input_tokens,
                output_tokens=vote.output_tokens,
                cache_read_tokens=vote.cache_read_tokens,
                error=vote.error,
            )
        )
    for hit in result.hits:
        session.add(_finding_row(event.id, hit))

    combined = fast_hits + result.hits
    score = fastgate.score_hits(combined)
    severity = _max_severity(
        combined, max(fastgate.severity_for_score(score), result.severity, key=lambda s: s.rank)
    )

    decision = get_policy().evaluate(
        ctx,
        combined,
        score,
        severity,
        council_action=result.recommended_action,
        council_confidence=result.confidence,
        council_summary=result.summary,
    )

    event.risk_score = score
    event.severity = severity
    event.council_status = result.status
    event.council_summary = _council_narrative(result)
    event.council_ms = result.elapsed_ms
    event.council_cost_usd = result.cost_usd

    escalated = alerts.action_escalated(prior_action, decision.action)
    if escalated:
        event.action = decision.action
        event.action_reason = f"{decision.reason}+retro"
        event.retro_escalated = True
    elif prior_action is Action.ALLOW and decision.action is Action.ALLOW:
        event.action_reason = decision.reason

    await session.commit()
    await session.refresh(event)
    await _broadcast(event, "event.escalated" if escalated else "event.updated")
    if escalated:
        _fire(alerts.dispatch(event, escalation=True))

    decision.message = decision.message.replace("{event_id}", event.id)
    return decision


def _council_narrative(result: CouncilResult) -> str:
    parts = [result.summary.strip()] if result.summary else []
    if result.dissent:
        parts.append(f"Dissent: {result.dissent.strip()}")
    if result.false_positive_risk and result.status in {"completed", "partial"}:
        parts.append(f"False-positive risk: {result.false_positive_risk}.")
    return " ".join(parts) or None


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------


async def _broadcast(event: ScanEvent, kind: str) -> None:
    try:
        await bus.publish(kind, EventOut.model_validate(event).model_dump(mode="json"))
    except Exception as exc:
        log.warning("broadcast failed: %s", exc)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


def _fire(coro) -> None:
    _spawn(coro)


async def drain_background(timeout: float = 30.0) -> None:
    """Let in-flight council passes finish on shutdown so their findings land."""
    if not _background:
        return
    await asyncio.wait(set(_background), timeout=timeout)


async def recent_events(session: AsyncSession, limit: int = 50) -> list[ScanEvent]:
    result = await session.execute(
        select(ScanEvent).order_by(ScanEvent.created_at.desc()).limit(limit)
    )
    return list(result.scalars())
