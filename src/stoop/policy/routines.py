"""Routine learning: what normally happens at this door, by weekday and hour.

A deliberately small model: weekly event rates per (key, weekday, hour) bucket with
half-weight smoothing from neighbouring hours. It answers two questions well enough for
front-door decisions: "how surprising is this event right now?" and "is it unusual that
nothing has happened?".
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from stoop.events import Event


class RoutineModel:
    def __init__(self, events: Iterable[Event], *, zone: ZoneInfo, days: int) -> None:
        self.zone = zone
        self.weeks = max(days / 7.0, 1.0)
        self.days = max(days, 1)
        self._counts: Counter[tuple[str, int, int]] = Counter()
        self._observed_days: set[str] = set()
        self._active_days: set[str] = set()
        self._first_activity: dict[str, int] = {}
        self._total = 0
        for ev in events:
            local = ev.occurred_at.astimezone(zone)
            day = local.date().isoformat()
            self._counts[(ev.key, local.weekday(), local.hour)] += 1
            self._total += 1
            self._observed_days.add(day)
            if ev.is_presence:
                self._active_days.add(day)
                self._first_activity[day] = min(self._first_activity.get(day, 24), local.hour)

    @property
    def sample_size(self) -> int:
        return self._total

    @property
    def is_cold(self) -> bool:
        """Too little history to trust anomaly scores."""
        return self._total < 20

    def rate(self, key: str, at: datetime) -> float:
        """Expected events per week for ``key`` in the hour bucket containing ``at``."""
        local = at.astimezone(self.zone)
        dow, hour = local.weekday(), local.hour
        c = self._counts[(key, dow, hour)]
        c += 0.5 * (self._counts[(key, dow, (hour - 1) % 24)] + self._counts[(key, dow, (hour + 1) % 24)])
        # Same hour on other weekdays contributes a little, so a weekday pattern generalizes.
        others = sum(self._counts[(key, d, hour)] for d in range(7) if d != dow)
        c += 0.15 * others
        return c / self.weeks

    def anomaly(self, key: str, at: datetime) -> float:
        """0 = routine, 1 = never seen at this time. Cold models return a neutral 0.5."""
        if self.is_cold:
            return 0.5
        return math.exp(-self.rate(key, at))

    def expects_daily_activity(self) -> bool:
        """True when most days with any activity also had a person at the door.

        Measured against observed days, not the calendar window, so gaps in data collection
        (or a backfill that stops short of today) do not read as "this home is usually quiet".
        """
        if len(self._observed_days) < 7:
            return False
        return len(self._active_days) >= 0.6 * len(self._observed_days)

    def usual_first_activity_hour(self) -> int | None:
        if not self._first_activity:
            return None
        hours = sorted(self._first_activity.values())
        return hours[len(hours) // 2]

    def busiest_hours(self, key: str | None = None, top: int = 3) -> list[tuple[int, float]]:
        per_hour: defaultdict[int, float] = defaultdict(float)
        for (k, _dow, hour), c in self._counts.items():
            if key is None or k == key:
                per_hour[hour] += c / self.weeks
        return sorted(per_hour.items(), key=lambda kv: kv[1], reverse=True)[:top]


def history_window(at: datetime, days: int) -> tuple[datetime, datetime]:
    return at - timedelta(days=days), at
