"""Direct scan endpoint.

Used by the browser extension (where there is no API call to proxy) and by any
service that wants a verdict without routing its traffic through the gateway.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app import pipeline
from app.db import get_session
from app.models import ScanEvent
from app.schemas import PromptContext, ScanRequest, ScanResponse

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def scan(
    payload: ScanRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    ctx = PromptContext(
        text=payload.text,
        source=payload.source,
        client_app=payload.client_app,
        provider=payload.provider,
        model=payload.model,
        actor=payload.actor or request.headers.get("x-scanner-actor"),
        actor_department=payload.actor_department
        or request.headers.get("x-scanner-department"),
        session_id=payload.session_id,
        src_ip=request.client.host if request.client else None,
        attachments=payload.attachments,
        metadata=payload.metadata,
    )

    verdict = await pipeline.evaluate(ctx, session)

    # Callers that cannot un-send (a browser paste into chatgpt.com) may block
    # on the council rather than accept a retroactive escalation.
    if payload.wait_for_council and verdict.council_status == "pending":
        result = await pipeline.review_now(ctx, verdict.hits)
        event = await session.get(ScanEvent, verdict.event_id)
        if event is not None:
            decision = await pipeline.apply_council(session, event, ctx, verdict.hits, result)
            verdict = verdict.model_copy(
                update={
                    "action": event.action,
                    "severity": event.severity,
                    "risk_score": event.risk_score,
                    "reason": event.action_reason or verdict.reason,
                    "council_status": event.council_status,
                    "council_summary": event.council_summary,
                    "hits": verdict.hits + result.hits,
                    "message": decision.message or verdict.message,
                }
            )

    return ScanResponse(
        event_id=verdict.event_id,
        action=verdict.action,
        severity=verdict.severity,
        risk_score=verdict.risk_score,
        reason=verdict.reason,
        message=verdict.message,
        findings=verdict.hits,
        redacted_text=verdict.redacted_text,
        council_status=verdict.council_status,
        council_summary=verdict.council_summary,
        fast_gate_ms=verdict.fast_gate_ms,
    )
