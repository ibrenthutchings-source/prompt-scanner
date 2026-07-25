"""WebSocket feed powering the dashboard's real-time view."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.db import session_scope
from app.events import bus
from app.models import ScanEvent
from app.schemas import EventOut

log = logging.getLogger(__name__)
router = APIRouter(tags=["live"])

_HEARTBEAT_S = 20.0


@router.websocket("/v1/live")
async def live_feed(websocket: WebSocket) -> None:
    await websocket.accept()

    # Backfill so a freshly opened tab is not empty until the next event.
    try:
        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(ScanEvent).order_by(ScanEvent.created_at.desc()).limit(40)
                )
            ).scalars()
            await websocket.send_json(
                {
                    "type": "backfill",
                    "data": [
                        EventOut.model_validate(e).model_dump(mode="json")
                        for e in reversed(list(rows))
                    ],
                }
            )
    except Exception as exc:
        log.warning("live backfill failed: %s", exc)

    try:
        async with bus.subscribe() as queue:
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_S)
                except TimeoutError:
                    # Keeps intermediaries from reaping an idle connection and
                    # tells the client the feed is alive rather than wedged.
                    await websocket.send_json({"type": "heartbeat"})
                    continue
                await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.info("live feed closed: %s", exc)
        with contextlib.suppress(Exception):
            await websocket.close()
