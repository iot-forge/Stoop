"""Policy engine: event + memory -> decision.

Deterministic rules run first and always produce a complete decision. An optional reasoner
may then refine wording and nudge severity by one step. Anything sensitive is flagged with
``requires_confirmation`` or a ``sensitive`` suggested action and is never auto-executed.

Runs on the ingestion path only. Query paths (dashboards, MCP tools) read the store and
stay well under Alexa+'s 500 ms tool budget.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from stoop.events import Detected, Event, EventKind
from stoop.memory.models import (
    SEVERITY_ORDER,
    Action,
    Decision,
    ExpectedVisit,
    Person,
    Role,
    Severity,
    Site,
    SiteKind,
    SuggestedAction,
    Visit,
    VisitStatus,
)
from stoop.memory.store import Store
from stoop.policy.routines import RoutineModel
from stoop.reasoning.base import Reasoner, ReasoningContext

log = logging.getLogger(__name__)

SnapshotFetcher = Callable[[Event], bytes | None]


@dataclass
class PolicyConfig:
    quiet_start_hour: int = 22
    quiet_end_hour: int = 7
    visit_gap_min: int = 10
    match_grace_min: int = 20
    anomaly_notify_threshold: float = 0.6
    linger_presence_count: int = 3
    linger_window_min: int = 8
    history_days: int = 28
    inactivity_hours: float = 30.0
    door_open_notify_min: int = 20
    package_at_risk_hours: float = 4.0
    repeat_suppression_min: int = 60
    refine_min_severity: Severity = Severity.MEDIUM
    refine_always: bool = False


@dataclass
class _Match:
    expected: ExpectedVisit
    person: Person | None
    window: tuple[datetime, datetime]


class PolicyEngine:
    def __init__(
        self,
        store: Store,
        *,
        config: PolicyConfig | None = None,
        reasoner: Reasoner | None = None,
        snapshot_fetcher: SnapshotFetcher | None = None,
    ) -> None:
        self.store = store
        self.config = config or PolicyConfig()
        self.reasoner = reasoner
        self.snapshot_fetcher = snapshot_fetcher
        self._routine_cache: dict[tuple[str, str], RoutineModel] = {}

    # ------------------------------------------------------------------ public
    def handle(self, event: Event, *, learn_only: bool = False) -> Decision | None:
        """Ingest one event. Returns the decision, or None when the event was a duplicate.

        ``learn_only`` stores the event and updates visits without producing a decision,
        which is how historical backfills are loaded.
        """
        site = self._site(event.site_id)
        if not self.store.put_event(event):
            return None
        self._routine_cache.pop((site.id, event.occurred_at.date().isoformat()), None)
        visit = self._sessionize(site, event)
        match = self._match_expected(site, event.occurred_at)
        if visit is not None and match is not None and visit.expected_visit_id is None:
            visit.expected_visit_id = match.expected.id
            visit.person_id = match.expected.person_id
            self.store.put_visit(visit)
        self._track_state(site, event)
        if learn_only:
            return None

        routine = self._routine(site, event.occurred_at)
        anomaly = routine.anomaly(event.key, event.occurred_at)
        local = event.occurred_at.astimezone(site.zone)
        decision = self._evaluate(site, event, visit, match, anomaly, local)
        decision = self._suppress_repeats(decision)
        decision = self._refine(site, event, visit, match, anomaly, local, decision)
        self.store.put_decision(decision)
        return decision

    def sweep(self, now: datetime | None = None) -> list[Decision]:
        """Periodic checks for things that did *not* happen: no-shows, inactivity, doors left open."""
        now = (now or datetime.now(tz=UTC)).astimezone(UTC)
        out: list[Decision] = []
        for site in self.store.list_sites():
            out.extend(self._sweep_site(site, now))
        return out

    def routine_for(self, site_id: str, at: datetime | None = None) -> RoutineModel:
        """The learned routine model for a site as of ``at`` (default: now)."""
        return self._routine(self._site(site_id), (at or datetime.now(tz=UTC)).astimezone(UTC))

    # ------------------------------------------------------------- internals
    def _site(self, site_id: str) -> Site:
        site = self.store.get_site(site_id)
        if site is None:
            site = self.store.put_site(Site(id=site_id, name=site_id))
        return site

    def _routine(self, site: Site, at: datetime) -> RoutineModel:
        key = (site.id, at.date().isoformat())
        model = self._routine_cache.get(key)
        if model is None:
            since = at - timedelta(days=self.config.history_days)
            events = [e for e in self.store.events(site.id, since=since, until=at) if e.occurred_at < at]
            model = RoutineModel(events, zone=site.zone, days=self.config.history_days)
            self._routine_cache[key] = model
        return model

    def _sessionize(self, site: Site, event: Event) -> Visit | None:
        if event.kind in (
            EventKind.DEVICE_ONLINE,
            EventKind.DEVICE_OFFLINE,
            EventKind.SENSOR_ALERT,
            EventKind.SENSOR_CLEARED,
            EventKind.OTHER,
        ):
            return None
        gap = timedelta(minutes=self.config.visit_gap_min)
        visit = self.store.open_visit(site.id)
        # abs(): an out-of-order (older) event must not be glued onto a newer visit.
        if visit is not None and abs(event.occurred_at - visit.last_event_at) > gap:
            visit.status = VisitStatus.CLOSED
            visit.ended_at = visit.last_event_at
            self.store.put_visit(visit)
            visit = None
        if visit is None:
            visit = Visit(site_id=site.id, started_at=event.occurred_at, last_event_at=event.occurred_at)
        visit.event_ids.append(event.id)
        visit.last_event_at = max(visit.last_event_at, event.occurred_at)
        if event.is_presence:
            visit.presence_count += 1
        if event.kind is EventKind.BUTTON_PRESS:
            visit.rang = True
        if event.kind is EventKind.DOOR_OPENED:
            visit.door_opened = True
        if event.kind is EventKind.MOTION and event.detected is Detected.PACKAGE:
            visit.package = True
        self.store.put_visit(visit)
        return visit

    def _match_expected(self, site: Site, at: datetime) -> _Match | None:
        grace = timedelta(minutes=self.config.match_grace_min)
        best: _Match | None = None
        for exp in self.store.expected(site.id):
            for ws, we in exp.windows_between(at - grace, at + grace, site.zone):
                if ws - grace <= at <= we + grace:
                    person = self.store.get_person(exp.person_id) if exp.person_id else None
                    cand = _Match(exp, person, (ws, we))
                    if best is None or (we - ws) < (best.window[1] - best.window[0]):
                        best = cand
        return best

    def _track_state(self, site: Site, event: Event) -> None:
        if event.kind is EventKind.DOOR_OPENED:
            self.store.set_state(site.id, f"door_open:{event.device_id}", event.occurred_at.isoformat())
        elif event.kind is EventKind.DOOR_CLOSED:
            self.store.set_state(site.id, f"door_open:{event.device_id}", None)
        elif event.kind is EventKind.DEVICE_OFFLINE:
            self.store.set_state(site.id, f"offline:{event.device_id}", event.occurred_at.isoformat())
        elif event.kind is EventKind.DEVICE_ONLINE:
            self.store.set_state(site.id, f"offline:{event.device_id}", None)
        if event.is_presence:
            self.store.set_state(site.id, "last_presence_at", event.occurred_at.isoformat())

    def _in_quiet_hours(self, local: datetime) -> bool:
        s, e = self.config.quiet_start_hour, self.config.quiet_end_hour
        h = local.hour
        return (h >= s or h < e) if s > e else (s <= h < e)

    # ----------------------------------------------------------------- rules
    def _evaluate(
        self,
        site: Site,
        ev: Event,
        visit: Visit | None,
        match: _Match | None,
        anomaly: float,
        local: datetime,
    ) -> Decision:
        cfg = self.config
        quiet = self._in_quiet_hours(local)
        when = local.strftime("%I:%M %p").lstrip("0")
        where = ev.device_name or "the front door"
        who = _who(match)
        family = [p for p in self.store.persons(site.id) if p.role is Role.FAMILY]
        d = _base(site, ev, visit, match, anomaly)

        def actions(*kinds: str, sensitive_kinds: tuple[str, ...] = ()) -> list[SuggestedAction]:
            out: list[SuggestedAction] = []
            for k in kinds:
                if k == "view_live":
                    out.append(SuggestedAction(kind=k, label="Look at the door now", payload={"device_id": ev.device_id}))
                elif k == "call_family" and family:
                    out.append(SuggestedAction(kind="call_person", label=f"Call {family[0].name}", target_person_id=family[0].id))
                elif k == "mark_expected":
                    out.append(SuggestedAction(kind=k, label="This visitor was expected", payload={"visit_id": visit.id if visit else None}))
                elif k == "contact_emergency":
                    out.append(SuggestedAction(kind=k, label="Contact emergency services", sensitive=True))
                elif k == "check_device":
                    out.append(SuggestedAction(kind=k, label="Check the device", payload={"device_id": ev.device_id}))
            for k in sensitive_kinds:
                out.append(SuggestedAction(kind=k, label=k.replace("_", " ").capitalize(), sensitive=True))
            return out

        k = ev.kind
        if k is EventKind.SENSOR_ALERT:
            label = (ev.sensor or "sensor").replace("_", " ")
            return d(
                Action.ESCALATE, Severity.HIGH, "sensor_alert",
                f"A {label} alert came from {where}.",
                f"{label.capitalize()} alert at {where} at {when}.",
                actions=actions("view_live", "call_family", "contact_emergency"),
                confidence=0.95, key=f"{ev.device_id}:{ev.sensor}",
            )
        if k is EventKind.SENSOR_CLEARED:
            return d(Action.LOG, Severity.INFO, "sensor_cleared", "Sensor alert cleared.", f"The {ev.sensor or 'sensor'} alert at {where} cleared.")
        if k is EventKind.DEVICE_OFFLINE:
            return d(Action.NOTIFY, Severity.LOW, "device_offline", "The device stopped reporting.", f"{where} went offline at {when}.", actions=actions("check_device"), key=ev.device_id)
        if k is EventKind.DEVICE_ONLINE:
            return d(Action.LOG, Severity.INFO, "device_online", "Device back online.", f"{where} is back online.")
        if k is EventKind.DOOR_CLOSED:
            return d(Action.LOG, Severity.INFO, "door_closed", "Door closed.", f"{where} closed at {when}.")
        if k is EventKind.LIVE_VIEW or k is EventKind.OTHER:
            return d(Action.LOG, Severity.INFO, k.value, "Informational event.", f"{k.value.replace('_', ' ').capitalize()} at {where}.")

        if k is EventKind.DOOR_OPENED:
            arrived_first = visit is not None and visit.presence_count > 0
            if match:
                return d(Action.LOG, Severity.INFO, "expected_entry", f"{who} is expected now.", f"{who} went in at {when}.")
            if quiet and not arrived_first and site.kind is SiteKind.HOME:
                return d(
                    Action.NOTIFY, Severity.HIGH, "night_door_open",
                    "The door opened during quiet hours with nobody seen outside first, which can mean someone left the house.",
                    f"{where} opened at {when} and nobody had come to the door first.",
                    actions=actions("view_live", "call_family"), confidence=0.8, key=visit.id if visit else None,
                )
            if not arrived_first:
                return d(Action.LOG, Severity.LOW, "door_open_from_inside", "Door opened from inside.", f"{where} opened from inside at {when}.")
            return d(Action.LOG, Severity.LOW, "door_opened", "Door opened after a visitor arrived.", f"{where} opened at {when}.")

        if k is EventKind.BUTTON_PRESS:
            if match:
                return d(
                    Action.NOTIFY, Severity.INFO, "expected_arrival", f"{who} is scheduled for this window.",
                    f"{who} arrived at {when}, as scheduled.", confidence=0.9, key=visit.id if visit else None,
                )
            if quiet:
                return d(
                    Action.NOTIFY, Severity.HIGH, "night_doorbell", "Doorbell during quiet hours with no expected visitor.",
                    f"Someone rang {where} at {when}. Nobody was expected.",
                    actions=actions("view_live", "call_family", "mark_expected"), confidence=0.85, key=visit.id if visit else None,
                )
            if visit is not None and visit.presence_count >= cfg.linger_presence_count and _within(visit, cfg.linger_window_min):
                return d(
                    Action.NOTIFY, Severity.MEDIUM, "lingering", "Repeated presence and ringing without being let in.",
                    f"Someone has been at {where} for several minutes and rang again at {when}.",
                    actions=actions("view_live", "call_family", "mark_expected"), confidence=0.75, key=visit.id,
                )
            return d(
                Action.NOTIFY, Severity.MEDIUM, "unknown_visitor", "Doorbell with no matching expected visit.",
                f"Someone rang {where} at {when}. Nobody was expected.",
                actions=actions("view_live", "mark_expected"), confidence=0.7, key=visit.id if visit else None,
            )

        # MOTION
        det = ev.detected or Detected.UNKNOWN
        if det is Detected.PACKAGE:
            return d(Action.NOTIFY, Severity.INFO, "package_delivered", "Camera saw a package.", f"A package was left at {where} at {when}.", confidence=0.8, key=visit.id if visit else None)
        if det in (Detected.VEHICLE, Detected.ANIMAL):
            if quiet and anomaly >= cfg.anomaly_notify_threshold:
                return d(Action.LOG, Severity.LOW, "night_vehicle", "Vehicle or animal during quiet hours.", f"A {det.value} passed {where} at {when}.")
            return d(Action.IGNORE, Severity.INFO, "routine_motion", "Routine non-person motion.", f"A {det.value} passed {where}.")
        if det in (Detected.MOTION, Detected.UNKNOWN):
            return d(Action.IGNORE, Severity.INFO, "routine_motion", "Unclassified motion.", f"Motion at {where}.")

        # human
        if match:
            return d(Action.LOG, Severity.INFO, "expected_presence", f"{who} is expected now.", f"{who} is at {where}.")
        if visit is not None and visit.presence_count >= cfg.linger_presence_count and _within(visit, cfg.linger_window_min):
            return d(
                Action.NOTIFY, Severity.MEDIUM, "lingering", "Someone has stayed at the door for several minutes.",
                f"Someone has been at {where} for several minutes without being let in.",
                actions=actions("view_live", "call_family", "mark_expected"), confidence=0.7, key=visit.id,
            )
        recent_package = self.store.decision_for_rule(
            site.id, "package_delivered", since=ev.occurred_at - timedelta(hours=cfg.package_at_risk_hours), until=ev.occurred_at
        )
        if recent_package and (visit is None or not visit.package):
            return d(
                Action.NOTIFY, Severity.MEDIUM, "package_at_risk", "A person approached while a package was waiting.",
                f"Someone is at {where} and a package was delivered earlier. Worth a look.",
                actions=actions("view_live"), confidence=0.6, key=visit.id if visit else None,
            )
        if quiet:
            return d(
                Action.NOTIFY, Severity.MEDIUM, "night_presence", "Person at the door during quiet hours.",
                f"Someone is at {where} at {when}.", actions=actions("view_live", "call_family"), confidence=0.7,
                key=visit.id if visit else None,
            )
        if anomaly >= cfg.anomaly_notify_threshold:
            return d(
                Action.NOTIFY, Severity.LOW, "unusual_time", "Person at the door at an unusual time for this home.",
                f"Someone is at {where} at {when}, which is unusual for this time.", actions=actions("view_live", "mark_expected"),
                confidence=0.55, key=visit.id if visit else None,
            )
        return d(Action.LOG, Severity.INFO, "routine_presence", "Person at the door at a normal time.", f"Someone is at {where}.")

    def _suppress_repeats(self, decision: Decision) -> Decision:
        if decision.action not in (Action.NOTIFY, Action.ESCALATE):
            return decision
        key = decision.metadata.get("key")
        if key is None:
            return decision
        since = decision.created_at - timedelta(minutes=self.config.repeat_suppression_min)
        prior = self.store.decision_for_rule(decision.site_id, decision.rule, since=since, until=decision.created_at, key=key)
        if prior is not None and prior.action in (Action.NOTIFY, Action.ESCALATE):
            decision.action = Action.LOG
            decision.metadata["suppressed_by"] = prior.id
        return decision

    def _refine(
        self,
        site: Site,
        ev: Event,
        visit: Visit | None,
        match: _Match | None,
        anomaly: float,
        local: datetime,
        decision: Decision,
    ) -> Decision:
        if self.reasoner is None or decision.action not in (Action.NOTIFY, Action.ESCALATE):
            return decision
        if not self.config.refine_always and _rank(decision.severity) < _rank(self.config.refine_min_severity):
            return decision
        snapshot = None
        if self.snapshot_fetcher is not None and ev.media:
            try:
                snapshot = self.snapshot_fetcher(ev)
            except Exception:  # noqa: BLE001
                log.exception("snapshot fetch failed")
        ctx = ReasoningContext(
            site=site,
            event=ev,
            decision=decision,
            local_time=local,
            visit=visit,
            matched_person=match.person if match else None,
            matched_expected=match.expected if match else None,
            recent_events=self.store.events(site.id, since=ev.occurred_at - timedelta(hours=24), until=ev.occurred_at, limit=50, newest_first=True),
            recent_decisions=self.store.decisions(site.id, since=ev.occurred_at - timedelta(hours=24), limit=20),
            anomaly_score=anomaly,
            known_people=self.store.persons(site.id),
            snapshot=snapshot,
        )
        try:
            ref = self.reasoner.refine(ctx)
        except Exception:  # noqa: BLE001
            log.exception("reasoner failed; keeping rule decision")
            return decision
        if ref is None:
            return decision
        decision.message = ref.message.strip() or decision.message
        if ref.reason:
            decision.reason = ref.reason.strip()
        if ref.severity is not None:
            cur, new = _rank(decision.severity), _rank(ref.severity)
            decision.severity = SEVERITY_ORDER[max(cur - 1, min(cur + 1, new))]
        decision.confidence = round((decision.confidence + ref.confidence) / 2, 2)
        decision.refined_by = self.reasoner.name
        if ref.observations:
            decision.metadata["observations"] = ref.observations
        return decision

    # ----------------------------------------------------------------- sweep
    def _sweep_site(self, site: Site, now: datetime) -> list[Decision]:
        cfg = self.config
        out: list[Decision] = []
        local = now.astimezone(site.zone)

        # Close stale visits.
        visit = self.store.open_visit(site.id)
        if visit is not None and now - visit.last_event_at > timedelta(minutes=cfg.visit_gap_min):
            visit.status = VisitStatus.CLOSED
            visit.ended_at = visit.last_event_at
            self.store.put_visit(visit)

        # Expected visits whose window closed without a matching visit.
        grace = timedelta(minutes=cfg.match_grace_min)
        for exp in self.store.expected(site.id):
            for ws, we in exp.windows_between(now - timedelta(hours=24), now, site.zone):
                if we + grace > now:
                    continue
                key = f"{exp.id}:{ws.date().isoformat()}"
                if self.store.decision_for_rule(site.id, "no_show", since=ws - timedelta(days=1), key=key):
                    continue
                matched = any(
                    v.expected_visit_id == exp.id and ws - grace <= v.started_at <= we + grace
                    for v in self.store.visits(site.id, since=ws - grace)
                )
                if matched:
                    continue
                person = self.store.get_person(exp.person_id) if exp.person_id else None
                who = person.name if person else exp.label
                dec = Decision(
                    site_id=site.id, event_id=None, created_at=now, action=Action.NOTIFY, severity=Severity.MEDIUM,
                    rule="no_show", reason=f"No visit matched the expected window {ws.astimezone(site.zone):%a %H:%M}-{we.astimezone(site.zone):%H:%M}.",
                    message=f"{who} did not show up for the {ws.astimezone(site.zone).strftime('%I:%M %p').lstrip('0')} visit.",
                    confidence=0.7, matched_expected_visit_id=exp.id, matched_person_id=exp.person_id,
                    suggested_actions=[SuggestedAction(kind="call_person", label=f"Call {who}", target_person_id=exp.person_id)] if exp.person_id else [],
                    metadata={"key": key},
                )
                out.append(self.store.put_decision(dec))

        # Inactivity (homes only, during the day, when history says the door is normally used daily).
        if site.kind is SiteKind.HOME and 9 <= local.hour <= 21:
            last = self.store.get_state(site.id, "last_presence_at")
            routine = self._routine(site, now)
            if last and (routine.expects_daily_activity() or site.metadata.get("expect_daily_activity")):
                last_at = datetime.fromisoformat(last)
                hours = (now - last_at).total_seconds() / 3600
                key = local.date().isoformat()
                if hours >= cfg.inactivity_hours and not self.store.decision_for_rule(site.id, "inactivity", since=now - timedelta(days=1), key=key):
                    out.append(
                        self.store.put_decision(
                            Decision(
                                site_id=site.id, event_id=None, created_at=now, action=Action.NOTIFY, severity=Severity.MEDIUM,
                                rule="inactivity", reason=f"No one has been at the door for {hours:.0f} hours; this home usually has daily activity.",
                                message=f"Nothing has happened at the front door for about {hours:.0f} hours, which is unusual for {site.name}.",
                                confidence=0.6, suggested_actions=[SuggestedAction(kind="call_resident", label="Check in by phone")],
                                metadata={"key": key},
                            )
                        )
                    )

        # Doors left open.
        for key_name, opened in self._door_states(site):
            minutes = (now - opened).total_seconds() / 60
            device_id = key_name.split(":", 1)[1]
            if minutes >= cfg.door_open_notify_min and not self.store.decision_for_rule(site.id, "door_left_open", since=opened, key=device_id):
                out.append(
                    self.store.put_decision(
                        Decision(
                            site_id=site.id, event_id=None, created_at=now, action=Action.NOTIFY, severity=Severity.LOW,
                            rule="door_left_open", reason=f"Contact sensor has reported open for {minutes:.0f} minutes.",
                            message=f"The door has been open for about {minutes:.0f} minutes.", confidence=0.8,
                            metadata={"key": device_id},
                        )
                    )
                )
        return out

    def _door_states(self, site: Site) -> list[tuple[str, datetime]]:
        return [
            (key, datetime.fromisoformat(value))
            for key, value in self.store.states_with_prefix(site.id, "door_open:").items()
            if value
        ]


# ---------------------------------------------------------------------- helpers
def _rank(s: Severity) -> int:
    return SEVERITY_ORDER.index(s)


def _within(visit: Visit, minutes: int) -> bool:
    return (visit.last_event_at - visit.started_at) <= timedelta(minutes=minutes)


def _who(match: _Match | None) -> str:
    if match is None:
        return "Someone"
    if match.person:
        role = match.person.role.value
        return f"{match.person.name} ({role})" if role != "other" else match.person.name
    return match.expected.label


def _base(site: Site, ev: Event, visit: Visit | None, match: _Match | None, anomaly: float):
    def make(
        action: Action,
        severity: Severity,
        rule: str,
        reason: str,
        message: str,
        *,
        actions: list[SuggestedAction] | None = None,
        confidence: float = 0.7,
        key: str | None = None,
    ) -> Decision:
        acts = actions or []
        return Decision(
            site_id=site.id,
            event_id=ev.id,
            visit_id=visit.id if visit else None,
            created_at=ev.occurred_at,
            action=action,
            severity=severity,
            rule=rule,
            reason=reason,
            message=message,
            confidence=confidence,
            anomaly_score=round(anomaly, 3),
            requires_confirmation=any(a.sensitive for a in acts),
            suggested_actions=acts,
            matched_person_id=match.person.id if match and match.person else None,
            matched_expected_visit_id=match.expected.id if match else None,
            metadata={"key": key} if key else {},
        )

    return make


__all__ = ["PolicyConfig", "PolicyEngine"]
