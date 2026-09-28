"""Policy engine: event + memory -> decision.

Deterministic rules from a :class:`RuleRegistry` run first and always produce a complete
decision. An optional reasoner may then refine wording and nudge severity by one step.
Anything sensitive is flagged with ``requires_confirmation`` or a ``sensitive`` suggested
action and is never auto-executed.

Runs on the ingestion path only. Query paths (dashboards, MCP tools) read the store and
stay well under Alexa+'s 500 ms tool budget.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from stoop.events import Detected, Event, EventKind
from stoop.memory.models import SEVERITY_ORDER, Action, Decision, Severity, Site, Visit, VisitStatus
from stoop.memory.store import Store
from stoop.policy.routines import RoutineModel
from stoop.policy.rules import Match, RuleContext, RuleRegistry, SweepContext, SweepRegistry
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


class PolicyEngine:
    def __init__(
        self,
        store: Store,
        *,
        config: PolicyConfig | None = None,
        reasoner: Reasoner | None = None,
        snapshot_fetcher: SnapshotFetcher | None = None,
        rules: RuleRegistry | None = None,
        sweeps: SweepRegistry | None = None,
    ) -> None:
        from stoop.policy.home_rules import home_rules, home_sweeps

        self.store = store
        self.config = config or PolicyConfig()
        self.reasoner = reasoner
        self.snapshot_fetcher = snapshot_fetcher
        self.rules = rules if rules is not None else home_rules()
        self.sweeps = sweeps if sweeps is not None else home_sweeps()
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
        if match is not None and match.departing and not self._departure_applies(site, event, visit):
            match = None
        # Only arrivals bind a visit to the schedule; a departure visit stays unbound so
        # "did they arrive?" checks keep looking at the arrival window.
        if visit is not None and match is not None and not match.departing and visit.expected_visit_id is None:
            visit.expected_visit_id = match.expected.id
            visit.person_id = match.expected.person_id
            self.store.put_visit(visit)
        self._track_state(site, event)
        if learn_only:
            return None

        routine = self._routine(site, event.occurred_at)
        local = event.occurred_at.astimezone(site.zone)
        ctx = RuleContext(
            site=site,
            event=event,
            local=local,
            config=self.config,
            store=self.store,
            visit=visit,
            match=match,
            anomaly=routine.anomaly(event.key, event.occurred_at),
            quiet=self._in_quiet_hours(local),
            people=self.store.persons(site.id),
        )
        decision = self.rules.evaluate(ctx)
        decision = self._suppress_repeats(decision)
        decision = self._refine(ctx, decision)
        self.store.put_decision(decision)
        self._supersede_earlier(decision)
        return decision

    def sweep(self, now: datetime | None = None) -> list[Decision]:
        """Periodic checks for things that did *not* happen: no-shows, inactivity, doors left open."""
        now = (now or datetime.now(tz=UTC)).astimezone(UTC)
        out: list[Decision] = []
        for site in self.store.list_sites():
            ctx = SweepContext(
                site=site, now=now, local=now.astimezone(site.zone), config=self.config, store=self.store,
                routine=self._routine(site, now), people=self.store.persons(site.id),
            )
            for d in self.sweeps.run(ctx):
                out.append(self.store.put_decision(d))
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
            # Events flagged raw["learn"] = False (e.g. replayed demo scenes) are judged but never
            # become "normal" for this door.
            events = [e for e in self.store.events(site.id, since=since, until=at) if e.occurred_at < at and e.raw.get("learn", True)]
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

    def _match_expected(self, site: Site, at: datetime) -> Match | None:
        grace = timedelta(minutes=self.config.match_grace_min)
        best: Match | None = None
        expected = self.store.expected(site.id)
        for exp in expected:
            for ws, we in exp.windows_between(at - grace, at + grace, site.zone):
                if ws - grace <= at <= we + grace:
                    person = self.store.get_person(exp.person_id) if exp.person_id else None
                    cand = Match(exp, person, (ws, we))
                    if best is None or (we - ws) < (best.window[1] - best.window[0]):
                        best = cand
        if best is not None:
            return best
        # Departure: a matched arrival earlier today whose expected stay has not run out yet.
        by_id = {e.id: e for e in expected}
        for visit in self.store.visits(site.id, since=at - timedelta(hours=24), limit=50):
            exp = by_id.get(visit.expected_visit_id or "")
            if exp is None or visit.started_at > at:
                continue
            stay = timedelta(minutes=exp.expected_duration_min or 0)
            window_end = max((we for ws, we in exp.windows_between(visit.started_at - grace, visit.started_at + grace, site.zone)), default=visit.started_at)
            deadline = max(window_end, visit.started_at + stay) + grace
            if visit.started_at <= at <= deadline:
                person = self.store.get_person(exp.person_id) if exp.person_id else None
                return Match(exp, person, (visit.started_at, deadline), phase="departure")
        return None

    def _departure_applies(self, site: Site, event: Event, visit: Visit | None) -> bool:
        """Is this event plausibly the expected visitor leaving, rather than someone else arriving?

        A doorbell press never is: the visitor is inside. A person outside counts only when the
        door just opened from inside during this visit, or when the home has no door sensor at all
        (camera-only homes cannot tell the difference, so the stay window is the best signal).
        """
        if event.kind is EventKind.BUTTON_PRESS:
            return False
        if event.kind in (EventKind.DOOR_OPENED, EventKind.DOOR_CLOSED):
            return True
        if event.kind is EventKind.MOTION:
            if visit is not None and visit.door_opened:
                return True
            return not self._has_door_sensor(site, event.occurred_at)
        return True

    def _has_door_sensor(self, site: Site, at: datetime) -> bool:
        since = at - timedelta(days=self.config.history_days)
        return bool(self.store.events(site.id, since=since, until=at, kinds=[EventKind.DOOR_OPENED, EventKind.DOOR_CLOSED], limit=1))

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

    def _supersede_earlier(self, decision: Decision) -> None:
        """One visitor, one alert: a new alert for the same visit retires earlier open ones of
        equal or lower severity, so "someone is at the door" folds into "someone rang".
        """
        if decision.action not in (Action.NOTIFY, Action.ESCALATE) or decision.visit_id is None:
            return
        rank = _rank(decision.severity)
        for earlier in self.store.decisions(decision.site_id, unacknowledged_only=True, limit=50):
            if earlier.id == decision.id or earlier.visit_id != decision.visit_id or earlier.severity is Severity.INFO:
                continue
            if _rank(earlier.severity) <= rank:
                earlier.acknowledged_at = decision.created_at
                earlier.acknowledged_by = f"superseded:{decision.id}"
                earlier.metadata["superseded_by"] = decision.id
                self.store.put_decision(earlier)

    def _refine(self, ctx: RuleContext, decision: Decision) -> Decision:
        if self.reasoner is None or decision.action not in (Action.NOTIFY, Action.ESCALATE):
            return decision
        if not self.config.refine_always and _rank(decision.severity) < _rank(self.config.refine_min_severity):
            return decision
        ev, site = ctx.event, ctx.site
        snapshot = None
        if self.snapshot_fetcher is not None and ev.media:
            try:
                snapshot = self.snapshot_fetcher(ev)
            except Exception:  # noqa: BLE001
                log.exception("snapshot fetch failed")
        rctx = ReasoningContext(
            site=site,
            event=ev,
            decision=decision,
            local_time=ctx.local,
            visit=ctx.visit,
            matched_person=ctx.match.person if ctx.match else None,
            matched_expected=ctx.match.expected if ctx.match else None,
            recent_events=self.store.events(site.id, since=ev.occurred_at - timedelta(hours=24), until=ev.occurred_at, limit=50, newest_first=True),
            recent_decisions=self.store.decisions(site.id, since=ev.occurred_at - timedelta(hours=24), limit=20),
            anomaly_score=ctx.anomaly,
            known_people=ctx.people,
            snapshot=snapshot,
        )
        try:
            ref = self.reasoner.refine(rctx)
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


def _rank(s: Severity) -> int:
    return SEVERITY_ORDER.index(s)


__all__ = ["PolicyConfig", "PolicyEngine"]
