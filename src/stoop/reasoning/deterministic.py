"""Offline reasoner: adds context to messages without any model call.

Keeps demos and tests fully reproducible and lets every app run with zero credentials.
"""

from __future__ import annotations

from datetime import timedelta

from stoop.memory.models import Action
from stoop.reasoning.base import Reasoner, ReasoningContext, Refinement


class DeterministicReasoner(Reasoner):
    name = "deterministic"

    def refine(self, ctx: ReasoningContext) -> Refinement | None:
        if ctx.decision.action not in (Action.NOTIFY, Action.ESCALATE):
            return None
        notes: list[str] = []
        since = ctx.event.occurred_at - timedelta(hours=24)
        similar = [
            d
            for d in ctx.recent_decisions
            if d.rule == ctx.decision.rule and d.created_at >= since and d.id != ctx.decision.id
        ]
        if similar:
            notes.append(f"This is the {_ordinal(len(similar) + 1)} time today.")
        if ctx.anomaly_score is not None and ctx.anomaly_score >= 0.8:
            notes.append("Nothing like this usually happens at this hour.")
        elif ctx.anomaly_score is not None and ctx.anomaly_score <= 0.2:
            notes.append("Activity at this hour is normal for this door.")
        if ctx.visit and ctx.visit.presence_count >= 3:
            mins = max(1, int((ctx.visit.last_event_at - ctx.visit.started_at).total_seconds() // 60))
            notes.append(f"They have been at the door for about {mins} minute{'s' if mins != 1 else ''}.")
        if not notes:
            return None
        return Refinement(
            message=f"{ctx.decision.message} {' '.join(notes)}",
            reason=ctx.decision.reason,
            severity=None,
            confidence=ctx.decision.confidence,
            observations=notes,
        )


def _ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"
