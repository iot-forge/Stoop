from __future__ import annotations

from datetime import UTC, timedelta
from zoneinfo import ZoneInfo

from conftest import MONDAY, TZ, local

from stoop import Action, Decision, EventKind, Severity, Store
from stoop.policy.routines import RoutineModel
from stoop.sources.synthetic import generate_baseline


def test_baseline_is_deterministic_and_learns_hours():
    a = generate_baseline(site_id="s", days=28, end=MONDAY.astimezone(UTC), tz=TZ, seed=3)
    b = generate_baseline(site_id="s", days=28, end=MONDAY.astimezone(UTC), tz=TZ, seed=3)
    assert [e.id for e in a] == [e.id for e in b]
    assert all(e.raw.get("synthetic") for e in a)

    model = RoutineModel(a, zone=ZoneInfo(TZ), days=28)
    assert not model.is_cold
    assert model.anomaly("motion:human", local(2026, 9, 22, 13, 15)) < model.anomaly("motion:human", local(2026, 9, 22, 3, 15))
    assert model.anomaly("motion:human", local(2026, 9, 22, 3, 15)) > 0.9
    assert model.expects_daily_activity()
    busiest = [h for h, _ in model.busiest_hours("motion:human", top=3)]
    assert 13 in busiest or 12 in busiest or 14 in busiest


def test_cold_model_is_neutral():
    model = RoutineModel([], zone=ZoneInfo(TZ), days=28)
    assert model.is_cold
    assert model.anomaly("motion:human", MONDAY) == 0.5


def test_store_roundtrip_and_queries(tmp_path):
    path = tmp_path / "stoop.db"
    store = Store(str(path))
    from stoop import Site
    from stoop.sources.synthetic import BUILTIN, play_scenario

    store.put_site(Site(id="s", name="S"))
    evs = play_scenario(BUILTIN["delivery"], site_id="s", start=MONDAY)
    assert all(store.put_event(e) for e in evs)
    assert not store.put_event(evs[0])
    assert [e.id for e in store.events("s")] == [e.id for e in evs]
    assert [e.kind for e in store.events("s", kinds=[EventKind.BUTTON_PRESS])] == [EventKind.BUTTON_PRESS]
    assert store.last_event("s").id == evs[-1].id

    d = store.put_decision(
        Decision(site_id="s", event_id=evs[1].id, action=Action.NOTIFY, severity=Severity.MEDIUM, rule="x", reason="r", message="m")
    )
    assert store.decisions("s", unacknowledged_only=True)[0].id == d.id
    store.acknowledge(d.id, by="dana")
    assert store.decisions("s", unacknowledged_only=True) == []
    assert store.get_decision(d.id).acknowledged_by == "dana"

    store.set_state("s", "k", {"a": 1})
    assert store.get_state("s", "k") == {"a": 1}
    store.close()

    # Persistence across reopen.
    again = Store(str(path))
    assert len(again.events("s")) == len(evs)
    assert again.get_site("s").name == "S"


def test_expected_visit_windows_expand_recurring():
    from datetime import time

    from stoop import ExpectedVisit

    exp = ExpectedVisit(site_id="s", label="aide", days_of_week=[0, 2], local_start=time(9, 0), local_end=time(10, 0))
    windows = exp.windows_between(local(2026, 9, 21, 0), local(2026, 9, 27, 23), ZoneInfo(TZ))
    starts = [w[0].astimezone(ZoneInfo(TZ)) for w in windows]
    assert [s.weekday() for s in starts] == [0, 2]
    assert all(s.hour == 9 for s in starts)
    one_off = ExpectedVisit(site_id="s", label="plumber", window_start=MONDAY, window_end=MONDAY + timedelta(hours=2))
    assert one_off.windows_between(MONDAY - timedelta(hours=1), MONDAY + timedelta(hours=1), ZoneInfo(TZ)) == [
        (MONDAY, MONDAY + timedelta(hours=2))
    ]


def test_unlearned_events_are_judged_but_not_taught(store):
    """Demo replays (learn=False) never make an odd hour look normal."""
    from datetime import UTC

    from stoop import PolicyEngine, Site
    from stoop.sources.synthetic import BUILTIN, generate_baseline, play_scenario

    store.put_site(Site(id="s", name="S", timezone=TZ))
    engine = PolicyEngine(store)
    for e in generate_baseline(site_id="s", days=28, end=MONDAY.astimezone(UTC), tz=TZ):
        engine.handle(e, learn_only=True)
    night = local(2026, 9, 22, 3, 10)
    for _ in range(4):  # replay the same scene four times at 3 AM on different nights
        for e in play_scenario(BUILTIN["delivery"], site_id="s", start=night, learn=False, label=f"demo-{_}"):
            engine.handle(e)
        night += timedelta(days=1)
    model = engine.routine_for("s", night)
    assert model.anomaly("motion:human", night) > 0.9  # still unusual
    # The same replays with learn=True would have lowered it.
    other = PolicyEngine(Store(":memory:"))
    other.store.put_site(Site(id="s", name="S", timezone=TZ))
    night = local(2026, 9, 22, 3, 10)
    for _ in range(4):
        for e in play_scenario(BUILTIN["delivery"], site_id="s", start=night, learn=True, label=f"live-{_}"):
            other.handle(e)
        night += timedelta(days=1)
    assert other.routine_for("s", night).anomaly("motion:human", night) < 0.9


def test_delete_site_removes_everything(store):
    from stoop import PolicyEngine, Site
    from stoop.sources.synthetic import BUILTIN, play_scenario

    store.put_site(Site(id="a", name="A"))
    store.put_site(Site(id="b", name="B"))
    eng = PolicyEngine(store)
    for sid in ("a", "b"):
        for e in play_scenario(BUILTIN["lingering_stranger"], site_id=sid, start=MONDAY):
            eng.handle(e)
    store.set_state("a", "k", 1)
    store.delete_site("a")
    assert store.get_site("a") is None and store.events("a") == [] and store.decisions("a") == [] and store.visits("a") == []
    assert store.get_state("a", "k") is None
    assert store.get_site("b") is not None and store.events("b")
