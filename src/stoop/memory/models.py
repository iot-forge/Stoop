"""Context memory: who is expected, what a site is, what happened, what was decided."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time, timedelta
from enum import StrEnum
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SiteKind(StrEnum):
    HOME = "home"
    RENTAL = "rental"
    OFFICE = "office"
    CLINIC = "clinic"


class Site(_Model):
    id: str
    name: str
    timezone: str = "America/New_York"
    kind: SiteKind = SiteKind.HOME
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


class Role(StrEnum):
    FAMILY = "family"
    AIDE = "aide"
    NURSE = "nurse"
    NEIGHBOR = "neighbor"
    COURIER = "courier"
    CLEANER = "cleaner"
    CONTRACTOR = "contractor"
    GUEST = "guest"
    OTHER = "other"


class Person(_Model):
    id: str = Field(default_factory=lambda: new_id("per"))
    site_id: str
    name: str
    role: Role = Role.OTHER
    phone: str | None = None
    email: str | None = None
    notes: str | None = None
    trusted: bool = True


class ExpectedVisit(_Model):
    """A visit window. Either one-off (``window_start``/``window_end``) or recurring
    (``days_of_week`` + ``local_start``/``local_end``)."""

    id: str = Field(default_factory=lambda: new_id("exp"))
    site_id: str
    label: str
    person_id: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    days_of_week: list[int] | None = None  # 0 = Monday
    local_start: time | None = None
    local_end: time | None = None
    expected_duration_min: int | None = None
    origin: str = "manual"  # manual | calendar | booking
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("window_start", "window_end")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expected-visit windows must be timezone-aware")
        return value

    @property
    def recurring(self) -> bool:
        return bool(self.days_of_week) and self.local_start is not None and self.local_end is not None

    def windows_between(self, t0: datetime, t1: datetime, zone: ZoneInfo) -> list[tuple[datetime, datetime]]:
        """Concrete windows overlapping [t0, t1]."""
        if not self.recurring:
            if self.window_start and self.window_end and self.window_end >= t0 and self.window_start <= t1:
                return [(self.window_start, self.window_end)]
            return []
        assert self.days_of_week is not None and self.local_start and self.local_end
        out: list[tuple[datetime, datetime]] = []
        day: date = (t0.astimezone(zone) - timedelta(days=1)).date()
        last: date = (t1.astimezone(zone) + timedelta(days=1)).date()
        while day <= last:
            if day.weekday() in self.days_of_week:
                ws = datetime.combine(day, self.local_start, tzinfo=zone)
                we = datetime.combine(day, self.local_end, tzinfo=zone)
                if we < ws:
                    we += timedelta(days=1)
                if we >= t0 and ws <= t1:
                    out.append((ws.astimezone(UTC), we.astimezone(UTC)))
            day += timedelta(days=1)
        return out


class VisitStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class Visit(_Model):
    """A cluster of events close in time at one site (someone came to the door)."""

    id: str = Field(default_factory=lambda: new_id("vis"))
    site_id: str
    started_at: datetime
    last_event_at: datetime
    ended_at: datetime | None = None
    status: VisitStatus = VisitStatus.OPEN
    event_ids: list[str] = Field(default_factory=list)
    presence_count: int = 0
    rang: bool = False
    door_opened: bool = False
    package: bool = False
    expected_visit_id: str | None = None
    person_id: str | None = None
    summary: str | None = None


class Action(StrEnum):
    IGNORE = "ignore"
    LOG = "log"
    NOTIFY = "notify"
    ESCALATE = "escalate"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]


class SuggestedAction(_Model):
    kind: str  # e.g. call_person, message_person, view_live, mark_expected, contact_emergency
    label: str
    sensitive: bool = False
    target_person_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class Decision(_Model):
    id: str = Field(default_factory=lambda: new_id("dec"))
    site_id: str
    event_id: str | None
    visit_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    action: Action
    severity: Severity
    rule: str
    reason: str
    message: str
    confidence: float = 0.7
    anomaly_score: float | None = None
    requires_confirmation: bool = False
    suggested_actions: list[SuggestedAction] = Field(default_factory=list)
    matched_person_id: str | None = None
    matched_expected_visit_id: str | None = None
    refined_by: str | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def needs_attention(self) -> bool:
        return self.action in (Action.NOTIFY, Action.ESCALATE) and self.acknowledged_at is None
