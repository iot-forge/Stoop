"""Synthetic events for demos, tests and routine bootstrapping.

Real Ring history from the Developer Playground contains no motion or doorbell events, so
apps built on ``stoop`` label synthetic history clearly and keep it swappable for real
webhooks. Everything here is deterministic given a ``seed``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from stoop.events import Detected, Event, EventKind, make_event_id

SOURCE = "synthetic"


@dataclass
class Step:
    offset_s: float
    kind: EventKind = EventKind.MOTION
    detected: Detected | None = None
    device_id: str = "doorbell"
    device_name: str | None = "Front Door"
    sensor: str | None = None


@dataclass
class Scenario:
    name: str
    description: str
    steps: list[Step] = field(default_factory=list)


def _s(offset: float, kind: str, detected: str | None = None, **kw: object) -> Step:
    return Step(
        offset,
        EventKind(kind),
        Detected(detected) if detected else None,
        **kw,  # type: ignore[arg-type]
    )


BUILTIN: dict[str, Scenario] = {
    "delivery": Scenario(
        "delivery",
        "Courier drives up, leaves a package, drives off.",
        [
            _s(0, "motion", "vehicle"),
            _s(8, "motion", "human"),
            _s(14, "button_press"),
            _s(22, "motion", "package"),
            _s(30, "motion", "vehicle"),
        ],
    ),
    "aide_visit": Scenario(
        "aide_visit",
        "Home aide arrives, rings, goes in, leaves 90 minutes later.",
        [
            _s(0, "motion", "human"),
            _s(6, "button_press"),
            _s(20, "door_opened", device_id="front-door-sensor", device_name="Front Door Sensor", sensor="contact"),
            _s(35, "door_closed", device_id="front-door-sensor", device_name="Front Door Sensor", sensor="contact"),
            _s(90 * 60, "door_opened", device_id="front-door-sensor", device_name="Front Door Sensor", sensor="contact"),
            _s(90 * 60 + 12, "door_closed", device_id="front-door-sensor", device_name="Front Door Sensor", sensor="contact"),
            _s(90 * 60 + 15, "motion", "human"),
        ],
    ),
    "lingering_stranger": Scenario(
        "lingering_stranger",
        "Someone stays at the door for several minutes and rings twice.",
        [
            _s(0, "motion", "human"),
            _s(40, "button_press"),
            _s(120, "motion", "human"),
            _s(200, "button_press"),
            _s(300, "motion", "human"),
        ],
    ),
    "night_door_open": Scenario(
        "night_door_open",
        "Front door opens from inside at night with nobody at the door first.",
        [
            _s(0, "door_opened", device_id="front-door-sensor", device_name="Front Door Sensor", sensor="contact"),
            _s(30, "motion", "human"),
        ],
    ),
    "no_show": Scenario("no_show", "Only a vehicle passes; nobody comes to the door.", [_s(0, "motion", "vehicle")]),
    "device_flap": Scenario("device_flap", "Doorbell drops offline and recovers.", [_s(0, "device_offline"), _s(45, "device_online")]),
}


def play_scenario(scenario: Scenario, *, site_id: str, start: datetime, label: str | None = None, learn: bool = True) -> list[Event]:
    """Materialize a scenario as events beginning at ``start`` (must be tz-aware).

    ``learn=False`` marks the events so the policy engine judges them but leaves them out of
    routine learning; use it for demo scenes replayed on top of real or baseline history.
    """
    if start.tzinfo is None:
        raise ValueError("start must be timezone-aware")
    label = label or scenario.name
    out: list[Event] = []
    for i, step in enumerate(sorted(scenario.steps, key=lambda s: s.offset_s)):
        at = start + timedelta(seconds=step.offset_s)
        key = f"{site_id}:{label}:{start.isoformat()}:{i}"  # site in the key: the same scene at two homes is two events
        out.append(
            Event(
                id=make_event_id(SOURCE, key),
                site_id=site_id,
                source=SOURCE,
                kind=step.kind,
                detected=step.detected,
                device_id=step.device_id,
                device_name=step.device_name,
                occurred_at=at,
                sensor=step.sensor,
                dedupe_key=key,
                raw={"scenario": scenario.name, "step": i, "synthetic": True, "label": label, "learn": learn},
            )
        )
    return out


@dataclass
class RoutineSpec:
    """A recurring visitor pattern used to fabricate believable history."""

    label: str
    days_of_week: tuple[int, ...]  # 0=Monday
    local_time: time
    jitter_min: int = 12
    scenario: str = "delivery"
    skip_probability: float = 0.1


DEFAULT_HOME_ROUTINES: list[RoutineSpec] = [
    RoutineSpec("mail", (0, 1, 2, 3, 4, 5), time(13, 10), 25, "delivery", 0.15),
    RoutineSpec("aide", (0, 2, 4), time(9, 0), 10, "aide_visit", 0.05),
    RoutineSpec("neighbor_walk", (0, 1, 2, 3, 4, 5, 6), time(7, 45), 15, "no_show", 0.3),
    RoutineSpec("evening_cars", (0, 1, 2, 3, 4), time(17, 30), 40, "no_show", 0.2),
]


def generate_baseline(
    *,
    site_id: str,
    days: int = 28,
    end: datetime,
    tz: str = "America/New_York",
    routines: list[RoutineSpec] | None = None,
    seed: int = 7,
) -> list[Event]:
    """Fabricate ``days`` of routine history ending at ``end``. Deterministic per seed."""
    if end.tzinfo is None:
        raise ValueError("end must be timezone-aware")
    rng = random.Random(seed)
    zone = ZoneInfo(tz)
    routines = routines if routines is not None else DEFAULT_HOME_ROUTINES
    local_end = end.astimezone(zone)
    out: list[Event] = []
    for d in range(days, -1, -1):
        day = (local_end - timedelta(days=d)).date()
        for spec in routines:
            if day.weekday() not in spec.days_of_week or rng.random() < spec.skip_probability:
                continue
            jitter = timedelta(minutes=rng.randint(-spec.jitter_min, spec.jitter_min))
            start = datetime.combine(day, spec.local_time, tzinfo=zone) + jitter
            if start.astimezone(end.tzinfo) > end:
                continue
            out.extend(play_scenario(BUILTIN[spec.scenario], site_id=site_id, start=start, label=spec.label))
    out.sort(key=lambda e: e.occurred_at)
    return out
