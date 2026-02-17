#!/usr/bin/env python3
"""NIP event bus (publish/subscribe) + in-memory event buffer.

This is the Phase 0.3 building block from NIP_Roadmap.md.pdf:
- Techniques and sensors publish events (device.discovered, port.opened, etc.)
- Multiple consumers can subscribe (knowledge graph adapter, UI streaming, etc.)

We also keep a bounded in-memory buffer so the UI can poll recent events without
standing up a separate message broker.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import threading
import uuid
from typing import Any, Callable, Deque, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_event_id(prefix: str = "evt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class NipEvent:
    id: str
    ts: str
    type: str
    source: str
    entity: str
    summary: str
    data: Dict[str, Any]


Subscriber = Callable[[NipEvent], None]


class EventBus:
    def __init__(self, *, max_events: int = 2000):
        self._events: Deque[NipEvent] = deque(maxlen=max(1, int(max_events)))
        self._subscribers: List[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def publish(
        self,
        *,
        event_type: str,
        source: str,
        entity: str,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> NipEvent:
        ev = NipEvent(
            id=str(event_id or new_event_id()),
            ts=str(ts or utc_now_iso()),
            type=str(event_type),
            source=str(source),
            entity=str(entity or ""),
            summary=str(summary or ""),
            data=dict(data or {}),
        )

        with self._lock:
            self._events.append(ev)
            subs = list(self._subscribers)

        for fn in subs:
            try:
                fn(ev)
            except Exception:
                # Subscribers must never be able to break the publisher path.
                pass
        return ev

    def list_events(self, *, limit: int = 200) -> List[Dict[str, Any]]:
        lim = max(1, int(limit))
        with self._lock:
            items = list(self._events)[-lim:]
        return [asdict(ev) for ev in items]

