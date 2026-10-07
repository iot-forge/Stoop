from __future__ import annotations

from datetime import timedelta

from conftest import MONDAY, local

from stoop import Action, Detected, EventKind, Severity
from stoop.sources.synthetic import BUILTIN, play_scenario


def _events(name: str, start, site_id="home-1"):
    return play_scenario(BUILTIN[name], site_id=site_id, start=start)


def test_expected_aide_arrival_is_calm(warm_engine, site, aide_schedule, people):
    events = _events("aide_visit", local(2026, 9, 21, 9, 4))  # Monday 09:04
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    ring = next(d for d in decisions if d.rule == "expected_arrival")
    assert ring.action is Action.NOTIFY and ring.severity is Severity.INFO
    assert "Maria" in ring.message and ring.matched_person_id == people["maria"].id
    assert not ring.requires_confirmation
    entry = next(d for d in decisions if d.rule == "expected_entry")
    assert entry.action is Action.LOG
    # One visit, matched to the schedule.
    visits = warm_engine.store.visits(site.id)
    assert any(v.expected_visit_id == aide_schedule.id for v in visits)


def test_unknown_visitor_at_night_is_high(warm_engine, site, people):
    events = _events("lingering_stranger", local(2026, 9, 21, 23, 40))
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    first_ring = next(d for d in decisions if d.rule == "night_doorbell")
    assert first_ring.action is Action.NOTIFY and first_ring.severity is Severity.HIGH
    assert any(a.kind == "call_person" for a in first_ring.suggested_actions)
    # The second ring in the same visit is suppressed to a log entry, not a second alert.
    later = [d for d in decisions if d.rule == "night_doorbell"][1:]
    assert all(d.action is Action.LOG and d.metadata.get("suppressed_by") for d in later)


def test_lingering_stranger_daytime(warm_engine, site):
    events = _events("lingering_stranger", local(2026, 9, 22, 15, 0))  # Tuesday 15:00
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    rules = [d.rule for d in decisions]
    assert "unknown_visitor" in rules
    assert "lingering" in rules
    linger = next(d for d in decisions if d.rule == "lingering")
    # Nobody rang: by day that is a note, worded as what the camera saw, not as someone waiting.
    assert linger.severity is Severity.INFO and linger.action is Action.NOTIFY
    assert linger.message.startswith("Movement near") and "let in" not in linger.message


def test_lingering_at_night_is_worth_a_look(warm_engine, site):
    events = _events("lingering_stranger", local(2026, 9, 22, 23, 40))
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    linger = next(d for d in decisions if d.rule == "lingering" and d.action is Action.NOTIFY)
    assert linger.severity is Severity.MEDIUM and "nobody rang" in linger.message


def test_sensor_alert_escalates_with_confirmation_gate(engine, site, people):
    from stoop.events import Event, make_event_id

    ev = Event(
        id=make_event_id("t", "co1"),
        site_id=site.id,
        source="test",
        kind=EventKind.SENSOR_ALERT,
        sensor="co",
        device_id="hallway",
        device_name="Hallway monitor",
        occurred_at=MONDAY,
        dedupe_key="co1",
    )
    d = engine.handle(ev)
    assert d and d.action is Action.ESCALATE and d.severity is Severity.HIGH
    assert d.requires_confirmation
    assert any(a.sensitive for a in d.suggested_actions)


def test_night_door_open_without_visitor(warm_engine, site, people):
    events = _events("night_door_open", local(2026, 9, 22, 2, 15))
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    assert decisions[0].rule == "night_door_open"
    assert decisions[0].severity is Severity.HIGH


def test_routine_mail_is_quiet_but_3am_is_not(warm_engine, site):
    mail = _events("delivery", local(2026, 9, 22, 13, 10))
    d_mail = [d for d in (warm_engine.handle(e) for e in mail) if d]
    human_mail = next(d for d in d_mail if d.event_id and warm_engine.store.get_event(d.event_id).detected is Detected.HUMAN)
    assert human_mail.anomaly_score is not None and human_mail.anomaly_score < 0.6

    night = _events("delivery", local(2026, 9, 23, 3, 10))
    d_night = [d for d in (warm_engine.handle(e) for e in night) if d]
    human_night = next(d for d in d_night if d.event_id and warm_engine.store.get_event(d.event_id).detected is Detected.HUMAN)
    assert human_night.anomaly_score > human_mail.anomaly_score
    assert human_night.action is Action.NOTIFY


def test_duplicate_event_is_ignored(engine, site):
    ev = _events("no_show", MONDAY)[0]
    assert engine.handle(ev) is not None
    assert engine.handle(ev) is None
    assert len(engine.store.events(site.id)) == 1


def test_package_then_stranger(warm_engine, site):
    delivery = _events("delivery", local(2026, 9, 22, 13, 10))
    for e in delivery:
        warm_engine.handle(e)
    later = _events("no_show", local(2026, 9, 22, 14, 30))  # vehicle only: ignored
    for e in later:
        warm_engine.handle(e)
    stranger = _events("lingering_stranger", local(2026, 9, 22, 14, 45))
    decisions = [d for d in (warm_engine.handle(e) for e in stranger) if d]
    assert decisions[0].rule == "package_at_risk"


def test_sweep_flags_no_show_and_inactivity(warm_engine, site, aide_schedule, people):
    # Nobody came Monday 09:00-10:30; sweep at 11:30 should flag it once.
    at = local(2026, 9, 21, 11, 30)
    first = warm_engine.sweep(at)
    no_show = [d for d in first if d.rule == "no_show"]
    assert len(no_show) == 1 and "Maria" in no_show[0].message
    assert warm_engine.sweep(at + timedelta(minutes=5)) == []  # no repeat

    # Two days of silence at a home that normally sees daily activity.
    quiet = local(2026, 9, 23, 15, 0)
    later = warm_engine.sweep(quiet)
    assert any(d.rule == "inactivity" for d in later)


def test_deterministic_reasoner_adds_context(store, site, people):
    from stoop import DeterministicReasoner, PolicyConfig, PolicyEngine

    eng = PolicyEngine(store, config=PolicyConfig(refine_always=True), reasoner=DeterministicReasoner())
    events = _events("lingering_stranger", local(2026, 9, 22, 23, 30))
    decisions = [d for d in (eng.handle(e) for e in events) if d]
    refined = [d for d in decisions if d.refined_by == "deterministic"]
    assert refined, "expected at least one refined decision"
    assert any("minute" in d.message or "time today" in d.message for d in refined)


def test_expected_departure_is_not_a_stranger(warm_engine, site, aide_schedule, people):
    """Aide arrives inside her window, leaves 90 minutes later in quiet hours: no alerts."""
    # Wednesday 9:50 arrival (window 9:00-10:30, stay 90 min) -> departure ~11:20, past window + grace.
    events = _events("aide_visit", local(2026, 9, 23, 9, 50))
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    rules = [d.rule for d in decisions]
    assert "expected_arrival" in rules and "expected_exit" in rules
    assert not any(d.action in (Action.NOTIFY, Action.ESCALATE) and d.severity is not Severity.INFO for d in decisions), rules
    # The departure events name her.
    assert any("Maria" in d.message and "left" in d.message for d in decisions)


def test_expected_departure_in_quiet_hours(store, site, people):
    from datetime import time

    from stoop import ExpectedVisit, PolicyEngine

    store.put_expected(
        ExpectedVisit(
            site_id=site.id,
            label="Evening aide",
            person_id=people["maria"].id,
            days_of_week=[0, 1, 2, 3, 4],
            local_start=time(21, 0),
            local_end=time(21, 30),
            expected_duration_min=90,
        )
    )
    engine = PolicyEngine(store)
    events = _events("aide_visit", local(2026, 9, 22, 21, 5))  # leaves ~22:35, inside quiet hours
    decisions = [d for d in (engine.handle(e) for e in events) if d]
    assert "night_door_open" not in [d.rule for d in decisions]
    assert "night_presence" not in [d.rule for d in decisions]
    assert "expected_exit" in [d.rule for d in decisions]
    # But a stranger two hours after she left is still a stranger.
    later = [d for d in (engine.handle(e) for e in _events("lingering_stranger", local(2026, 9, 23, 0, 40))) if d]
    assert any(d.rule == "night_doorbell" for d in later)


def test_stranger_during_aide_stay_still_alerts(store, site, people):
    """A ring while the aide is inside is not the aide leaving; it is a visitor to judge."""
    from datetime import time

    from stoop import ExpectedVisit, PolicyEngine

    store.put_expected(
        ExpectedVisit(
            site_id=site.id,
            label="Evening aide",
            person_id=people["maria"].id,
            days_of_week=[0, 1, 2, 3, 4],
            local_start=time(21, 0),
            local_end=time(21, 30),
            expected_duration_min=90,
        )
    )
    engine = PolicyEngine(store)
    # Arrival only (first four steps: motion, ring, door open, door close) at 21:05.
    arrival = _events("aide_visit", local(2026, 9, 22, 21, 5))[:4]
    for e in arrival:
        engine.handle(e)
    # An hour later, past the arrival window but inside her stay, a stranger lingers and rings twice.
    stranger = [d for d in (engine.handle(e) for e in _events("lingering_stranger", local(2026, 9, 22, 22, 5))) if d]
    rules = [d.rule for d in stranger]
    assert "unknown_visitor" in rules or "night_doorbell" in rules, rules
    assert not any("Maria" in d.message for d in stranger)
    # Her real departure (door opens from inside, then she is seen outside) is still hers.
    exit_events = _events("aide_visit", local(2026, 9, 22, 21, 5))[4:]
    departure = [d for d in (engine.handle(e) for e in exit_events) if d]
    assert "expected_exit" in [d.rule for d in departure]
    assert not any(d.action in (Action.NOTIFY, Action.ESCALATE) for d in departure)


def test_one_visitor_one_open_alert(warm_engine, site, people):
    """A night courier: presence alert, then the ring upgrades it. Only the ring stays open."""
    events = _events("delivery", local(2026, 9, 22, 23, 59))
    decisions = [d for d in (warm_engine.handle(e) for e in events) if d]
    rules = [d.rule for d in decisions]
    assert "night_presence" in rules and "night_doorbell" in rules
    open_alerts = warm_engine.store.decisions(site.id, unacknowledged_only=True)
    open_rules = [d.rule for d in open_alerts if d.severity is not Severity.INFO]
    assert open_rules == ["night_doorbell"], open_rules
    presence = next(d for d in warm_engine.store.decisions(site.id, limit=50) if d.rule == "night_presence")
    assert presence.acknowledged_by and presence.acknowledged_by.startswith("superseded:")
    # The package note is informational and stays.
    assert any(d.rule == "package_delivered" for d in open_alerts)


def test_night_door_open_is_a_single_alert(warm_engine, site, people):
    """Door opens from inside at night, then the resident is seen outside: one alert, not two."""
    for e in play_scenario(BUILTIN["delivery"], site_id=site.id, start=local(2026, 9, 22, 20, 30)):
        warm_engine.handle(e)  # a package from earlier must not turn the resident into a "risk"
    decisions = [d for d in (warm_engine.handle(e) for e in _events("night_door_open", local(2026, 9, 23, 2, 15))) if d]
    rules = [(d.rule, d.action.value) for d in decisions]
    assert rules == [("night_door_open", "notify"), ("stepped_outside", "log")], rules


def test_quiet_hours_per_site(store, site, people):
    """A home can set its own quiet hours; 8:30 PM is quiet when the home says quiet starts at 8."""
    from stoop import PolicyEngine

    site.metadata["quiet_start"] = 20
    site.metadata["quiet_end"] = 6
    store.put_site(site)
    engine = PolicyEngine(store)
    assert engine.quiet_hours(site) == (20, 6)
    decisions = [d for d in (engine.handle(e) for e in _events("lingering_stranger", local(2026, 9, 22, 20, 30))) if d]
    assert "night_doorbell" in [d.rule for d in decisions]
    # Same hour at a home with default quiet hours (22-7) is an ordinary unknown visitor.
    other = store.put_site(type(site)(id="home-2", name="Other", timezone=site.timezone))
    decisions = [d for d in (engine.handle(e) for e in _events("lingering_stranger", local(2026, 9, 22, 20, 30), site_id=other.id)) if d]
    assert "unknown_visitor" in [d.rule for d in decisions] and "night_doorbell" not in [d.rule for d in decisions]


def test_delete_person(store, site, people):
    store.delete_person(people["sam"].id) if "sam" in people else store.delete_person(people["maria"].id)
    assert all(p.name != ("Sam" if "sam" in people else "Maria") for p in store.persons(site.id))


def test_sensor_alerts_are_graded(engine, site, people):
    """Tamper is a chore, temperature is worth a look, carbon monoxide is an emergency."""
    from stoop.events import Event, make_event_id

    def ev(sensor, key):
        return Event(
            id=make_event_id("t", key),
            site_id=site.id,
            source="test",
            kind=EventKind.SENSOR_ALERT,
            sensor=sensor,
            device_id=f"dev-{sensor}",
            device_name="Outside Door Sensor",
            occurred_at=MONDAY,
            dedupe_key=key,
        )

    tamper = engine.handle(ev("tamper", "k1"))
    assert tamper.rule == "sensor_tamper" and tamper.severity is Severity.LOW and not tamper.requires_confirmation
    temp = engine.handle(ev("temperature", "k2"))
    assert temp.rule == "sensor_comfort" and temp.severity is Severity.MEDIUM and not temp.requires_confirmation
    co = engine.handle(ev("co", "k3"))
    assert co.rule == "sensor_alert" and co.action is Action.ESCALATE and co.requires_confirmation
