"""Operational endpoints: policy reload, health, self-test."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import get_settings
from app.council import get_council
from app.detect import fastgate
from app.events import bus
from app.policy.engine import reload_policy

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.post("/policy/reload")
async def reload() -> dict:
    engine = reload_policy()
    return {"version": engine.version, "rules": len(engine.rules), "exemptions": len(engine.exemptions)}


@router.get("/status")
async def status() -> dict:
    settings = get_settings()
    council = get_council()
    return {
        "council": {
            "enabled": settings.council_enabled,
            "available": council.available,
            "specialist_model": settings.council_specialist_model,
            "adjudicator_model": settings.council_adjudicator_model,
        },
        "shadow_mode": settings.shadow_mode,
        "ner_available": fastgate.ner_available(),
        "live_feed_subscribers": bus.subscriber_count,
    }
