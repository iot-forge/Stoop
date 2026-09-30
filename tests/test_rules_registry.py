from __future__ import annotations

import pytest
from conftest import local

from stoop import Action, Decision, EventKind, PolicyEngine, Severity, SiteKind
from stoop.policy import RuleContext, RuleRegistry, SweepContext, home_rules, home_sweeps
from stoop.sources.synthetic import BUILTIN, play_scenario


def _play(engine: PolicyEngine, name: str, start, site_id="home-1"):
    return [d for d in (engine.handle(e) for e in play_scenario(BUILTIN[name], site_id=site_id, start=start)) if d]


def test_default_registry_is_ordered_and_named():
    reg = home_rules()
    names = reg.names()
    assert names[0] == "sensor_maintenance" and names[-1] == "routine_presence"
    assert names.index("lingering") < names.index("stepped_outside") < names.index("package_at_risk")
    assert names.index("expected_arrival") < names.index("night_doorbell") < names.index("unknown_visitor")
    assert names.index("package_at_risk") < names.index("night_presence") < names.index("unusual_time")
    assert "night_door_open" in reg and reg.get("night_door_open").description.startswith("Door opens in quiet hours")
    assert home_sweeps().names() == ["close_stale_visits", "no_show", "inactivity", "door_left_open"]


def test_registry_mutations():
    reg = home_rules()
    n = len(reg)

    def custom(ctx: RuleContext) -> Decision | None:
        return None

    reg.add(custom, name="custom", before="unknown_visitor", kinds={EventKind.BUTTON_PRESS})
    assert len(reg) == n + 1 and reg.names().index("custom") == reg.names().index("unknown_visitor") - 1
    with pytest.raises(ValueError):
        reg.add(custom, name="custom")
    reg.add(custom, name="custom", replace=True)
    reg.move("custom", after="routine_presence")
    assert reg.names()[-1] == "custom"
    reg.disable("custom")
    assert "custom" not in reg.names(enabled_only=True)
    reg.enable("custom")
    reg.remove("custom")
    assert "custom" not in reg
    with pytest.raises(KeyError):
        reg.remove("custom")
    with pytest.raises(KeyError):
        reg.add(custom, name="x", before="nope")
    # Copies are independent.
    a, b = home_rules(), home_rules()
    a.disable("unknown_visitor")
    assert "unknown_visitor" in b.names(enabled_only=True)


def test_custom_rule_wins_over_default(warm_engine, site, store):
    rules = home_rules()

    @rules.add(before="unknown_visitor", kinds={EventKind.BUTTON_PRESS})
    def lunch_courier(ctx: RuleContext) -> Decision | None:
        """Weekday lunch doorbells at an office are couriers."""
        if 11 <= ctx.local.hour < 14 and ctx.site.kind is SiteKind.OFFICE:
            return ctx.decide(Action.LOG, Severity.INFO, "lunch_courier", "Lunch delivery window.", f"Lunch delivery at {ctx.where}.")
        return None

    assert rules.get("lunch_courier").description == "Weekday lunch doorbells at an office are couriers."
    site.kind = SiteKind.OFFICE
    store.put_site(site)
    engine = PolicyEngine(store, rules=rules)
    decisions = _play(engine, "delivery", local(2026, 9, 22, 12, 30))
    rules_fired = [d.rule for d in decisions]
    assert "lunch_courier" in rules_fired and "unknown_visitor" not in rules_fired
    # Outside the window the default still applies.
    later = _play(engine, "delivery", local(2026, 9, 22, 16, 30))
    assert "unknown_visitor" in [d.rule for d in later]


def test_disabling_a_rule_changes_outcome(warm_engine, site):
    engine = warm_engine
    for e in play_scenario(BUILTIN["delivery"], site_id=site.id, start=local(2026, 9, 22, 13, 10)):
        engine.handle(e)
    engine.rules.disable("package_at_risk")
    decisions = _play(engine, "lingering_stranger", local(2026, 9, 22, 14, 45))
    assert decisions[0].rule != "package_at_risk"
    assert decisions[0].rule in ("routine_presence", "unusual_time")


def test_replace_rule_and_fallback():
    reg = RuleRegistry()
    assert reg.names() == []
    reg.add(lambda ctx: None, name="noop")
    reg.replace("noop", lambda ctx: ctx.decide(Action.IGNORE, Severity.INFO, "replaced", "r", "m"))
    from stoop import Store

    store = Store(":memory:")
    engine = PolicyEngine(store, rules=reg)
    d = _play(engine, "no_show", local(2026, 9, 22, 12))[0]
    assert d.rule == "replaced"
    engine.rules.disable("noop")
    d2 = _play(engine, "device_flap", local(2026, 9, 22, 12))[0]
    assert d2.rule == "unmatched" and d2.action is Action.LOG


def test_custom_sweep_check(warm_engine, site, people):
    sweeps = home_sweeps()

    @sweeps.add(before="no_show")
    def weekly_reassurance(ctx: SweepContext) -> list[Decision]:
        key = f"week:{ctx.local.isocalendar().week}"
        if ctx.local.weekday() != 6 or ctx.already_decided("weekly_reassurance", key=key, since=ctx.now.replace(hour=0)):
            return []
        return [
            ctx.decide(Action.NOTIFY, Severity.INFO, "weekly_reassurance", "Sunday digest.", f"A normal week at {ctx.site.name}.", key=key)
        ]

    warm_engine.sweeps = sweeps
    sunday = local(2026, 9, 27, 18)
    first = warm_engine.sweep(sunday)
    assert any(d.rule == "weekly_reassurance" for d in first)
    assert not any(d.rule == "weekly_reassurance" for d in warm_engine.sweep(sunday))
    sweeps.disable("inactivity")
    assert "inactivity" not in sweeps.names(enabled_only=True)


def test_registries_are_per_engine():
    from stoop import Store

    a = PolicyEngine(Store(":memory:"))
    b = PolicyEngine(Store(":memory:"))
    a.rules.disable("unknown_visitor")
    assert "unknown_visitor" in b.rules.names(enabled_only=True)
