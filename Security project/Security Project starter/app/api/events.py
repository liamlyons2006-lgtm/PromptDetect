"""Server-Sent Events (SSE) stream management.

Manages a list of per-client async queues and provides helpers to:
- Register / deregister connected clients.
- Broadcast events (result, progress, demo_complete) to all clients.
- Serve the SSE response generator consumed by FastAPI.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator

logger = logging.getLogger(__name__)

# Sentinel object used to signal client disconnection / shutdown
_CLOSE = object()


class EventBroadcaster:
    """Manages SSE client queues and event broadcasting."""

    def __init__(self) -> None:
        self._clients: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def add_client(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._clients.append(queue)

    async def remove_client(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            try:
                self._clients.remove(queue)
            except ValueError:
                pass

    async def broadcast(self, event_type: str, data: dict) -> None:
        """Send an SSE event to all connected clients.

        Clients that fail to receive the event (e.g. disconnected) are
        removed silently.
        """
        payload = json.dumps(data, default=str)
        message = f"event: {event_type}\ndata: {payload}\n\n"

        async with self._lock:
            live_clients = list(self._clients)

        dead: list[asyncio.Queue] = []
        for q in live_clients:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead.append(q)
            except Exception:
                dead.append(q)

        for q in dead:
            await self.remove_client(q)

    async def close_all(self) -> None:
        """Signal all clients to close their connections."""
        async with self._lock:
            for q in self._clients:
                try:
                    q.put_nowait(_CLOSE)
                except Exception:
                    pass
            self._clients.clear()

    async def sse_generator(
        self,
        queue: asyncio.Queue,
        initial_state: dict | None = None,
    ) -> AsyncGenerator[str, None]:
        """Async generator that yields SSE-formatted messages.

        Sends an optional initial state snapshot immediately on connection,
        then streams subsequent broadcast events.
        """
        # Send initial state snapshot so new clients are immediately in sync
        if initial_state is not None:
            yield f"event: init\ndata: {json.dumps(initial_state, default=str)}\n\n"

        try:
            while True:
                try:
                    # Wait up to 30 seconds, then send a keep-alive comment
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue

                if message is _CLOSE:
                    break

                yield message
        finally:
            await self.remove_client(queue)


# Module-level singleton imported by routes
broadcaster = EventBroadcaster()
