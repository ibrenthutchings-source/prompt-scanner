"""In-process pub/sub for the dashboard's live feed.

Deliberately not Redis. A single gateway process holds the WebSocket
connections it serves, and slow consumers are dropped rather than allowed to
apply backpressure to the request path — a laggy dashboard tab must never slow
down prompt enforcement. Swap in Redis pub/sub here when you run more than one
replica behind a load balancer.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

log = logging.getLogger(__name__)

_QUEUE_DEPTH = 200


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = {"type": event_type, "data": payload}
        async with self._lock:
            targets = list(self._subscribers)
        for queue in targets:
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop the oldest item and retry once; if the consumer is still
                # wedged it will simply miss events rather than block us.
                with contextlib.suppress(asyncio.QueueEmpty, asyncio.QueueFull):
                    queue.get_nowait()
                    queue.put_nowait(message)

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_DEPTH)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


bus = EventBus()
