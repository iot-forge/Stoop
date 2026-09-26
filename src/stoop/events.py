"""Normalized front-door events.

Every source (Ring webhooks, Ring history, synthetic scenarios, other devices) is
converted into :class:`Event` so the memory, policy and reasoning layers never see
vendor-specific shapes.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventKind(StrEnum):
    MOTION = "motion"
    BUTTON_PRESS = "button_press"
    LIVE_VIEW = "live_view"
    DOOR_OPENED = "door_opened"
    DOOR_CLOSED = "door_closed"
    DEVICE_ONLINE = "device_online"
    DEVICE_OFFLINE = "device_offline"
    SENSOR_ALERT = "sensor_alert"
    SENSOR_CLEARED = "sensor_cleared"
    OTHER = "other"


class Detected(StrEnum):
    """What a camera believes it saw. Only motion events carry this."""

    HUMAN = "human"
    VEHICLE = "vehicle"
    ANIMAL = "animal"
    PACKAGE = "package"
    MOTION = "motion"
    UNKNOWN = "unknown"


class MediaRef(BaseModel):
    """Pointer to media that an app can fetch later (never the bytes themselves)."""

    model_config = ConfigDict(extra="forbid")

    kind: str  # snapshot | clip | live
    device_id: str
    at: datetime | None = None
    url: str | None = None
    content_type: str | None = None


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    site_id: str
    source: str
    kind: EventKind
    device_id: str
    occurred_at: datetime
    detected: Detected | None = None
    device_name: str | None = None
    sensor: str | None = None  # flood, freeze, tamper, co, ... for SENSOR_* kinds
    media: list[MediaRef] = Field(default_factory=list)
    dedupe_key: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)

    @property
    def key(self) -> str:
        """Routine-model bucket key, e.g. ``motion:human`` or ``button_press``."""
        if self.kind is EventKind.MOTION:
            return f"motion:{(self.detected or Detected.UNKNOWN).value}"
        return self.kind.value

    @property
    def is_presence(self) -> bool:
        """True when a person is plausibly at the door."""
        return self.kind is EventKind.BUTTON_PRESS or (
            self.kind is EventKind.MOTION and self.detected is Detected.HUMAN
        )


def make_event_id(source: str, dedupe_key: str) -> str:
    """Stable id derived from the source's own unique key, so replays never duplicate."""
    return hashlib.sha1(f"{source}:{dedupe_key}".encode()).hexdigest()[:20]
