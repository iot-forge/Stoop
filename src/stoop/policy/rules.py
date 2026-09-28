"""Rule registry: ordered, named, pluggable rules and sweep checks.

A *rule* looks at one event in context and either returns a :class:`Decision` or ``None``
to pass. The first rule that decides wins, so order is meaning: put specific rules before
general ones. A *sweep check* looks at a site at a point in time and returns zero or more
decisions about things that did not happen.

Apps extend the defaults without forking::

    from stoop.policy import home_rules

    rules = home_rules()

    @rules.add(before="unknown_visitor", kinds={EventKind.BUTTON_PRESS})
    def lunch_courier(ctx: RuleContext) -> Decision | None:
        if 11 <= ctx.local.hour < 14 and ctx.site.kind is SiteKind.OFFICE:
            return ctx.decide(Action.LOG, Severity.INFO, "lunch_courier", "Lunch delivery window.", f"Lunch delivery at {ctx.where}.")
        return None

    rules.disable("package_at_risk")
    engine = PolicyEngine(store, rules=rules)
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from stoop.events import Event, EventKind
from stoop.memory.models import (
    Action,
    Decision,
    ExpectedVisit,
    Person,
    Role,
    Severity,
    Site,
    SuggestedAction,
    Visit,
)

if TYPE_CHECKING:
    from stoop.memory.store import Store
    from stoop.policy.engine import PolicyConfig
    from stoop.policy.routines import RoutineModel


@dataclass
class Match:
    """An expected visit that explains the event.

    ``phase`` is ``"arrival"`` when the event falls inside the expected window, or
    ``"departure"`` when it follows a matched arrival within the expected duration, so an
    aide leaving 90 minutes after she arrived is not judged as a stranger at the door.
    """

    expected: ExpectedVisit
    person: Person | None
    window: tuple[datetime, datetime]
    phase: str = "arrival"

    @property
    def departing(self) -> bool:
        return self.phase == "departure"


@dataclass
class RuleContext:
    site: Site
    event: Event
    local: datetime
    config: PolicyConfig
    store: Store
    visit: Visit | None = None
    match: Match | None = None
    anomaly: float = 0.5
    quiet: bool = False
    people: list[Person] = field(default_factory=list)

    # ------------------------------------------------------------ readables
    @property
    def kind(self) -> EventKind:
        return self.event.kind

    @property
    def when(self) -> str:
        return self.local.strftime("%I:%M %p").lstrip("0")

    @property
    def where(self) -> str:
        return self.event.device_name or "the front door"

    @property
    def who(self) -> str:
        if self.match is None:
            return "Someone"
        if self.match.person:
            role = self.match.person.role.value
            return f"{self.match.person.name} ({role})" if role != "other" else self.match.person.name
        return self.match.expected.label

    @property
    def family(self) -> list[Person]:
        return [p for p in self.people if p.role is Role.FAMILY]

    @property
    def arrived_first(self) -> bool:
        """Someone was seen outside earlier in this visit (before this event)."""
        return self.visit is not None and self.visit.presence_count > (1 if self.event.is_presence else 0)

    @property
    def lingering(self) -> bool:
        v, c = self.visit, self.config
        return v is not None and v.presence_count >= c.linger_presence_count and (v.last_event_at - v.started_at) <= timedelta(minutes=c.linger_window_min)

    def recent_decision(self, rule: str, *, hours: float, key: str | None = None) -> Decision | None:
        """A decision with ``rule`` in the ``hours`` before this event (never from its future)."""
        return self.store.decision_for_rule(self.site.id, rule, since=self.event.occurred_at - timedelta(hours=hours), until=self.event.occurred_at, key=key)

    # ------------------------------------------------------------- builders
    def actions(self, *kinds: str) -> list[SuggestedAction]:
        out: list[SuggestedAction] = []
        family = self.family
        for k in kinds:
            if k == "view_live":
                out.append(SuggestedAction(kind=k, label="Look at the door now", payload={"device_id": self.event.device_id}))
            elif k == "call_family" and family:
                out.append(SuggestedAction(kind="call_person", label=f"Call {family[0].name}", target_person_id=family[0].id))
            elif k == "mark_expected":
                out.append(SuggestedAction(kind=k, label="This visitor was expected", payload={"visit_id": self.visit.id if self.visit else None}))
            elif k == "contact_emergency":
                out.append(SuggestedAction(kind=k, label="Contact emergency services", sensitive=True))
            elif k == "check_device":
                out.append(SuggestedAction(kind=k, label="Check the device", payload={"device_id": self.event.device_id}))
        return out

    def decide(
        self,
        action: Action,
        severity: Severity,
        rule: str,
        reason: str,
        message: str,
        *,
        actions: list[SuggestedAction] | None = None,
        confidence: float = 0.7,
        key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        acts = actions or []
        meta = dict(metadata or {})
        if key:
            meta["key"] = key
        return Decision(
            site_id=self.site.id,
            event_id=self.event.id,
            visit_id=self.visit.id if self.visit else None,
            created_at=self.event.occurred_at,
            action=action,
            severity=severity,
            rule=rule,
            reason=reason,
            message=message,
            confidence=confidence,
            anomaly_score=round(self.anomaly, 3),
            requires_confirmation=any(a.sensitive for a in acts),
            suggested_actions=acts,
            matched_person_id=self.match.person.id if self.match and self.match.person else None,
            matched_expected_visit_id=self.match.expected.id if self.match else None,
            metadata=meta,
        )

    @property
    def visit_key(self) -> str | None:
        return self.visit.id if self.visit else None


Rule = Callable[[RuleContext], "Decision | None"]


@dataclass
class RuleSpec:
    name: str
    fn: Rule
    kinds: frozenset[EventKind] | None = None
    enabled: bool = True
    description: str = ""


class RuleRegistry:
    """Ordered rules. First rule that returns a decision wins."""

    def __init__(self, rules: Iterable[RuleSpec] = ()) -> None:
        self._rules: list[RuleSpec] = list(rules)

    # ------------------------------------------------------------ mutation
    def add(
        self,
        fn: Rule | None = None,
        *,
        name: str | None = None,
        kinds: Iterable[EventKind] | None = None,
        before: str | None = None,
        after: str | None = None,
        replace: bool = False,
        description: str = "",
    ) -> Any:
        """Register a rule (usable as a decorator). Position with ``before``/``after``; default is last."""

        def register(f: Rule) -> Rule:
            spec = RuleSpec(name or f.__name__, f, frozenset(kinds) if kinds else None, True, description or (f.__doc__ or "").strip())
            existing = self._index(spec.name)
            if existing is not None:
                if not replace:
                    raise ValueError(f"rule {spec.name!r} already exists; pass replace=True")
                self._rules[existing] = spec
                return f
            if before is not None:
                self._rules.insert(self._require(before), spec)
            elif after is not None:
                self._rules.insert(self._require(after) + 1, spec)
            else:
                self._rules.append(spec)
            return f

        return register(fn) if fn is not None else register

    def replace(self, name: str, fn: Rule) -> None:
        idx = self._require(name)
        old = self._rules[idx]
        self._rules[idx] = RuleSpec(name, fn, old.kinds, old.enabled, (fn.__doc__ or old.description or "").strip())

    def remove(self, name: str) -> None:
        del self._rules[self._require(name)]

    def disable(self, name: str) -> None:
        self._rules[self._require(name)].enabled = False

    def enable(self, name: str) -> None:
        self._rules[self._require(name)].enabled = True

    def move(self, name: str, *, before: str | None = None, after: str | None = None) -> None:
        spec = self._rules.pop(self._require(name))
        if before is not None:
            self._rules.insert(self._require(before), spec)
        elif after is not None:
            self._rules.insert(self._require(after) + 1, spec)
        else:
            self._rules.append(spec)

    # ------------------------------------------------------------ queries
    def names(self, *, enabled_only: bool = False) -> list[str]:
        return [r.name for r in self._rules if r.enabled or not enabled_only]

    def get(self, name: str) -> RuleSpec:
        return self._rules[self._require(name)]

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self._index(name) is not None

    def copy(self) -> RuleRegistry:
        return RuleRegistry(RuleSpec(r.name, r.fn, r.kinds, r.enabled, r.description) for r in self._rules)

    # ---------------------------------------------------------- evaluation
    def evaluate(self, ctx: RuleContext) -> Decision:
        for spec in self._rules:
            if not spec.enabled or (spec.kinds is not None and ctx.kind not in spec.kinds):
                continue
            decision = spec.fn(ctx)
            if decision is not None:
                return decision
        return ctx.decide(Action.LOG, Severity.INFO, "unmatched", "No rule claimed this event.", f"{ctx.kind.value.replace('_', ' ').capitalize()} at {ctx.where}.")

    def _index(self, name: str) -> int | None:
        for i, r in enumerate(self._rules):
            if r.name == name:
                return i
        return None

    def _require(self, name: str) -> int:
        idx = self._index(name)
        if idx is None:
            raise KeyError(f"no rule named {name!r}; known: {self.names()}")
        return idx


# -------------------------------------------------------------------- sweeps
@dataclass
class SweepContext:
    site: Site
    now: datetime
    local: datetime
    config: PolicyConfig
    store: Store
    routine: RoutineModel
    people: list[Person] = field(default_factory=list)

    def already_decided(self, rule: str, *, key: str, since: datetime) -> bool:
        return self.store.decision_for_rule(self.site.id, rule, since=since, key=key) is not None

    def decide(
        self,
        action: Action,
        severity: Severity,
        rule: str,
        reason: str,
        message: str,
        *,
        key: str,
        actions: list[SuggestedAction] | None = None,
        confidence: float = 0.7,
        expected: ExpectedVisit | None = None,
    ) -> Decision:
        acts = actions or []
        return Decision(
            site_id=self.site.id,
            event_id=None,
            created_at=self.now,
            action=action,
            severity=severity,
            rule=rule,
            reason=reason,
            message=message,
            confidence=confidence,
            requires_confirmation=any(a.sensitive for a in acts),
            suggested_actions=acts,
            matched_expected_visit_id=expected.id if expected else None,
            matched_person_id=expected.person_id if expected else None,
            metadata={"key": key},
        )


SweepCheck = Callable[[SweepContext], list[Decision]]


@dataclass
class SweepSpec:
    name: str
    fn: SweepCheck
    enabled: bool = True
    description: str = ""


class SweepRegistry:
    """Ordered sweep checks. Every enabled check runs; decisions are concatenated."""

    def __init__(self, checks: Iterable[SweepSpec] = ()) -> None:
        self._checks: list[SweepSpec] = list(checks)

    def add(self, fn: SweepCheck | None = None, *, name: str | None = None, before: str | None = None, replace: bool = False) -> Any:
        def register(f: SweepCheck) -> SweepCheck:
            spec = SweepSpec(name or f.__name__, f, True, (f.__doc__ or "").strip())
            idx = self._index(spec.name)
            if idx is not None:
                if not replace:
                    raise ValueError(f"sweep check {spec.name!r} already exists; pass replace=True")
                self._checks[idx] = spec
            elif before is not None:
                self._checks.insert(self._require(before), spec)
            else:
                self._checks.append(spec)
            return f

        return register(fn) if fn is not None else register

    def remove(self, name: str) -> None:
        del self._checks[self._require(name)]

    def disable(self, name: str) -> None:
        self._checks[self._require(name)].enabled = False

    def enable(self, name: str) -> None:
        self._checks[self._require(name)].enabled = True

    def names(self, *, enabled_only: bool = False) -> list[str]:
        return [c.name for c in self._checks if c.enabled or not enabled_only]

    def copy(self) -> SweepRegistry:
        return SweepRegistry(SweepSpec(c.name, c.fn, c.enabled, c.description) for c in self._checks)

    def run(self, ctx: SweepContext) -> list[Decision]:
        out: list[Decision] = []
        for spec in self._checks:
            if spec.enabled:
                out.extend(spec.fn(ctx))
        return out

    def _index(self, name: str) -> int | None:
        for i, c in enumerate(self._checks):
            if c.name == name:
                return i
        return None

    def _require(self, name: str) -> int:
        idx = self._index(name)
        if idx is None:
            raise KeyError(f"no sweep check named {name!r}; known: {self.names()}")
        return idx
