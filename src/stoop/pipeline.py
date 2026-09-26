"""Ingestion pipeline: source event -> policy engine -> sinks.

Sinks receive decisions that need a human (``notify``/``escalate``). Apps plug in their own:
push notifications, SMS, an Alexa+ proactive message, a dashboard websocket.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Protocol, runtime_checkable

from stoop.events import Event
from stoop.memory.models import Action, Decision
from stoop.policy.engine import PolicyEngine

log = logging.getLogger(__name__)


@runtime_checkable
class Sink(Protocol):
    def deliver(self, decision: Decision, event: Event | None) -> None: ...


class LogSink:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or log

    def deliver(self, decision: Decision, event: Event | None) -> None:
        self._log.info("[%s/%s] %s", decision.action.value, decision.severity.value, decision.message)


class CallbackSink:
    def __init__(self, fn: Callable[[Decision, Event | None], None]) -> None:
        self._fn = fn

    def deliver(self, decision: Decision, event: Event | None) -> None:
        self._fn(decision, event)


class Pipeline:
    def __init__(self, engine: PolicyEngine, sinks: Iterable[Sink] = (), *, deliver_actions: Iterable[Action] = (Action.NOTIFY, Action.ESCALATE)) -> None:
        self.engine = engine
        self.sinks = list(sinks)
        self.deliver_actions = set(deliver_actions)

    def ingest(self, event: Event) -> Decision | None:
        decision = self.engine.handle(event)
        if decision is not None:
            self._dispatch(decision, event)
        return decision

    def ingest_many(self, events: Iterable[Event]) -> list[Decision]:
        out: list[Decision] = []
        for ev in sorted(events, key=lambda e: e.occurred_at):
            d = self.ingest(ev)
            if d is not None:
                out.append(d)
        return out

    def backfill(self, events: Iterable[Event]) -> int:
        """Load history for routine learning without producing decisions. Returns count stored."""
        n = 0
        for ev in sorted(events, key=lambda e: e.occurred_at):
            before = self.engine.store.get_event(ev.id) is not None
            self.engine.handle(ev, learn_only=True)
            n += 0 if before else 1
        return n

    def sweep(self, now: datetime | None = None) -> list[Decision]:
        decisions = self.engine.sweep(now)
        for d in decisions:
            self._dispatch(d, None)
        return decisions

    def _dispatch(self, decision: Decision, event: Event | None) -> None:
        if decision.action not in self.deliver_actions:
            return
        for sink in self.sinks:
            try:
                sink.deliver(decision, event)
            except Exception:  # noqa: BLE001 - one bad sink must not block others
                log.exception("sink %r failed", sink)
