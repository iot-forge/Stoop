"""Reasoner contract: optional refinement of a rule-based decision.

Rules always run first and produce a complete :class:`Decision`. A reasoner may improve the
wording, adjust severity by at most one step, and add context. It can never remove a
confirmation requirement, so a sensitive action always stays behind a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from stoop.events import Event
from stoop.memory.models import Decision, ExpectedVisit, Person, Severity, Site, Visit


@dataclass
class ReasoningContext:
    site: Site
    event: Event
    decision: Decision
    local_time: datetime
    visit: Visit | None = None
    matched_person: Person | None = None
    matched_expected: ExpectedVisit | None = None
    recent_events: list[Event] = field(default_factory=list)
    recent_decisions: list[Decision] = field(default_factory=list)
    anomaly_score: float | None = None
    known_people: list[Person] = field(default_factory=list)
    snapshot: bytes | None = None
    snapshot_format: str = "jpeg"


class Refinement(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: str
    reason: str | None = None
    severity: Severity | None = None
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    observations: list[str] = Field(default_factory=list)
    # Which reasoner actually wrote it, when a reasoner delegates to a fallback.
    by: str | None = None


@runtime_checkable
class Reasoner(Protocol):
    name: str

    def refine(self, ctx: ReasoningContext) -> Refinement | None: ...
