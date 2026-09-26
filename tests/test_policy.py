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
    assert linger.severity is Severity.MEDIUM


def test_sensor_alert_escalates_with_confirmation_gate(engine, site, people):
    from stoop.events import Event, make_event_id

    ev = Event(
        id=make_event_id("t", "co1"), site_id=site.id, source="test", kind=EventKind.SENSOR_ALERT, sensor="co",
        device_id="hallway", device_name="Hallway monitor", occurred_at=MONDAY, dedupe_key="co1",
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
