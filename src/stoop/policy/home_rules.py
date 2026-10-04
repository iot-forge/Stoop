"""The default rule set: a home whose door is watched for someone who lives there.

Each rule is small and named after the ``rule`` string it emits, so a decision can always
be traced back to the code that made it. Order matters: specific before general.
"""

from __future__ import annotations

from datetime import timedelta

from stoop.events import Detected, EventKind
from stoop.memory.models import Action, Decision, Severity, SiteKind, SuggestedAction, VisitStatus
from stoop.policy.rules import RuleContext, RuleRegistry, SweepContext, SweepRegistry

K = EventKind

# ------------------------------------------------------------------ sensors & devices


MAINTENANCE_SENSORS = {"tamper"}
COMFORT_SENSORS = {"temperature", "humidity", "pm25"}


def sensor_maintenance(ctx: RuleContext) -> Decision | None:
    """Tamper usually means a cover is loose or a sensor was knocked off its mount: a chore, not an emergency."""
    if ctx.event.sensor not in MAINTENANCE_SENSORS:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.LOW,
        "sensor_tamper",
        f"{ctx.where} reports its cover is open or it was moved.",
        f"{ctx.where} reports tampering at {ctx.when}. Usually the cover isn't fully closed; worth checking it's mounted.",
        actions=ctx.actions("check_device"),
        confidence=0.8,
        key=f"{ctx.event.device_id}:tamper",
    )


def sensor_comfort(ctx: RuleContext) -> Decision | None:
    """Temperature, humidity and air quality out of range: worth a look, not an emergency."""
    if ctx.event.sensor not in COMFORT_SENSORS:
        return None
    label = (ctx.event.sensor or "sensor").replace("pm25", "air quality").replace("_", " ")
    reading = _reading_text(ctx)
    if reading:
        direction = ctx.event.raw.get("direction")
        words = {"high": ("warm", "damp"), "low": ("cold", "dry")}
        word = words.get(direction, ("out of range", "out of range"))[0 if ctx.event.sensor == "temperature" else 1]
        message = f"{ctx.where} is {reading}. That is {word} for this home."
        rel = {"high": "above", "low": "below"}.get(direction, "outside")
        reason = f"{label.capitalize()} {reading} at {ctx.where} at {ctx.when}, {rel} its comfort range."
    else:
        reason = f"{label.capitalize()} is outside its normal range at {ctx.where}."
        message = f"{label.capitalize()} alert at {ctx.where} at {ctx.when}."
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "sensor_comfort",
        reason,
        message,
        actions=ctx.actions("call_family"),
        confidence=0.8,
        key=f"{ctx.event.device_id}:{ctx.event.sensor}",
    )


def sensor_alert(ctx: RuleContext) -> Decision | None:
    """Flood, freeze, carbon monoxide and similar: escalate, with emergency contact behind a confirmation."""
    label = (ctx.event.sensor or "sensor").replace("_", " ")
    return ctx.decide(
        Action.ESCALATE,
        Severity.HIGH,
        "sensor_alert",
        f"A {label} alert came from {ctx.where}.",
        f"{label.capitalize()} alert at {ctx.where} at {ctx.when}.",
        actions=ctx.actions("view_live", "call_family", "contact_emergency"),
        confidence=0.95,
        key=f"{ctx.event.device_id}:{ctx.event.sensor}",
    )


def sensor_cleared(ctx: RuleContext) -> Decision | None:
    return ctx.decide(
        Action.LOG,
        Severity.INFO,
        "sensor_cleared",
        "Sensor alert cleared.",
        f"The {ctx.event.sensor or 'sensor'} alert at {ctx.where} cleared.",
    )


def device_offline(ctx: RuleContext) -> Decision | None:
    return ctx.decide(
        Action.NOTIFY,
        Severity.LOW,
        "device_offline",
        "The device stopped reporting.",
        f"{ctx.where} went offline at {ctx.when}.",
        actions=ctx.actions("check_device"),
        key=ctx.event.device_id,
    )


def device_online(ctx: RuleContext) -> Decision | None:
    return ctx.decide(Action.LOG, Severity.INFO, "device_online", "Device back online.", f"{ctx.where} is back online.")


_ACCOUNT_TEXT = {
    "app_integration_added": "Connected to Ring.",
    "app_integration_removed": "Disconnected from Ring.",
    "device_added": "{where} was shared with this app.",
    "device_removed": "{where} is no longer shared with this app.",
    "subscription_activated": "Ring subscription active.",
    "subscription_deactivated": "Ring subscription ended; some features may stop working.",
}


def account_change(ctx: RuleContext) -> Decision | None:
    """Account housekeeping from Ring. Recorded for the audit trail, never shown as door activity."""
    text = _ACCOUNT_TEXT.get(ctx.event.sensor or "", "Ring account update.").format(where=ctx.event.device_name or "A device")
    return ctx.decide(Action.IGNORE, Severity.INFO, "account_change", "Account change reported by Ring.", text)


def informational(ctx: RuleContext) -> Decision | None:
    k = ctx.kind.value
    return ctx.decide(Action.LOG, Severity.INFO, k, "Informational event.", f"{k.replace('_', ' ').capitalize()} at {ctx.where}.")


# ---------------------------------------------------------------------------- doors


def door_closed(ctx: RuleContext) -> Decision | None:
    return ctx.decide(Action.LOG, Severity.INFO, "door_closed", "Door closed.", f"{ctx.where} closed at {ctx.when}.")


def expected_entry(ctx: RuleContext) -> Decision | None:
    """Door opens while an expected visitor is arriving, or leaving within their expected stay."""
    if ctx.match is None:
        return None
    if ctx.match.departing:
        return ctx.decide(
            Action.LOG,
            Severity.INFO,
            "expected_exit",
            f"{ctx.who} arrived earlier and is within the expected stay.",
            f"{ctx.who} left at {ctx.when}.",
        )
    return ctx.decide(Action.LOG, Severity.INFO, "expected_entry", f"{ctx.who} is expected now.", f"{ctx.who} went in at {ctx.when}.")


def night_door_open(ctx: RuleContext) -> Decision | None:
    """Door opens in quiet hours with nobody seen outside first: someone may have left the house."""
    if not (ctx.quiet and not ctx.arrived_first and ctx.site.kind is SiteKind.HOME):
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.HIGH,
        "night_door_open",
        "The door opened during quiet hours with nobody seen outside first, which can mean someone left the house.",
        f"{ctx.where} opened at {ctx.when} and nobody had come to the door first.",
        actions=ctx.actions("view_live", "call_family"),
        confidence=0.8,
        key=ctx.visit_key,
    )


def door_open_from_inside(ctx: RuleContext) -> Decision | None:
    if ctx.arrived_first:
        return None
    return ctx.decide(
        Action.LOG, Severity.LOW, "door_open_from_inside", "Door opened from inside.", f"{ctx.where} opened from inside at {ctx.when}."
    )


def door_opened(ctx: RuleContext) -> Decision | None:
    return ctx.decide(Action.LOG, Severity.LOW, "door_opened", "Door opened after a visitor arrived.", f"{ctx.where} opened at {ctx.when}.")


# ------------------------------------------------------------------------- doorbell


def expected_arrival(ctx: RuleContext) -> Decision | None:
    if ctx.match is None:
        return None
    if ctx.match.departing:
        return ctx.decide(
            Action.LOG,
            Severity.INFO,
            "expected_presence",
            f"{ctx.who} is still within the expected stay.",
            f"{ctx.who} rang {ctx.where} at {ctx.when} on the way out.",
        )
    return ctx.decide(
        Action.NOTIFY,
        Severity.INFO,
        "expected_arrival",
        f"{ctx.who} is scheduled for this window.",
        f"{ctx.who} arrived at {ctx.when}, as scheduled.",
        confidence=0.9,
        key=ctx.visit_key,
    )


def night_doorbell(ctx: RuleContext) -> Decision | None:
    if not ctx.quiet:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.HIGH,
        "night_doorbell",
        "Doorbell during quiet hours with no expected visitor.",
        f"Someone rang {ctx.where} at {ctx.when}. Nobody was expected.",
        actions=ctx.actions("view_live", "call_family", "mark_expected"),
        confidence=0.85,
        key=ctx.visit_key,
    )


def lingering_ring(ctx: RuleContext) -> Decision | None:
    if not ctx.lingering:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "lingering",
        "Repeated presence and ringing without being let in.",
        f"Someone has been at {ctx.where} for several minutes and rang again at {ctx.when}.",
        actions=ctx.actions("view_live", "call_family", "mark_expected"),
        confidence=0.75,
        key=ctx.visit_key,
    )


def unknown_visitor(ctx: RuleContext) -> Decision | None:
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "unknown_visitor",
        "Doorbell with no matching expected visit.",
        f"Someone rang {ctx.where} at {ctx.when}. Nobody was expected.",
        actions=ctx.actions("view_live", "mark_expected"),
        confidence=0.7,
        key=ctx.visit_key,
    )


# --------------------------------------------------------------------------- motion


def package_delivered(ctx: RuleContext) -> Decision | None:
    if ctx.event.detected is not Detected.PACKAGE:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.INFO,
        "package_delivered",
        "Camera saw a package.",
        f"A package was left at {ctx.where} at {ctx.when}.",
        confidence=0.8,
        key=ctx.visit_key,
    )


def non_person_motion(ctx: RuleContext) -> Decision | None:
    det = ctx.event.detected or Detected.UNKNOWN
    if det is Detected.HUMAN or det is Detected.PACKAGE:
        return None
    if det in (Detected.VEHICLE, Detected.ANIMAL) and ctx.quiet and ctx.anomaly >= ctx.config.anomaly_notify_threshold:
        return ctx.decide(
            Action.LOG,
            Severity.LOW,
            "night_vehicle",
            "Vehicle or animal during quiet hours.",
            f"A {det.value} passed {ctx.where} at {ctx.when}.",
        )
    if det in (Detected.VEHICLE, Detected.ANIMAL):
        return ctx.decide(
            Action.IGNORE, Severity.INFO, "routine_motion", "Routine non-person motion.", f"A {det.value} passed {ctx.where}."
        )
    return ctx.decide(Action.IGNORE, Severity.INFO, "routine_motion", "Unclassified motion.", f"Motion at {ctx.where}.")


def expected_presence(ctx: RuleContext) -> Decision | None:
    if ctx.match is None:
        return None
    if ctx.match.departing:
        return ctx.decide(
            Action.LOG, Severity.INFO, "expected_presence", f"{ctx.who} is still within the expected stay.", f"{ctx.who} is on the way out."
        )
    return ctx.decide(Action.LOG, Severity.INFO, "expected_presence", f"{ctx.who} is expected now.", f"{ctx.who} is at {ctx.where}.")


def lingering(ctx: RuleContext) -> Decision | None:
    if not ctx.lingering:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "lingering",
        "Someone has stayed at the door for several minutes.",
        f"Someone has been at {ctx.where} for several minutes without being let in.",
        actions=ctx.actions("view_live", "call_family", "mark_expected"),
        confidence=0.7,
        key=ctx.visit_key,
    )


def stepped_outside(ctx: RuleContext) -> Decision | None:
    """First person seen right after the door opened from inside: someone went out, not came in.

    The door-open decision already said what matters (and alerted if it was night), so this is
    a quiet entry rather than a second alert for the same moment.
    """
    v = ctx.visit
    if v is None or not v.door_opened or v.presence_count != 1:
        return None
    return ctx.decide(
        Action.LOG,
        Severity.LOW,
        "stepped_outside",
        "The door opened from inside just before this person was seen.",
        f"Someone stepped outside at {ctx.when}.",
    )


def package_at_risk(ctx: RuleContext) -> Decision | None:
    """A person shows up while a recently delivered package is still out."""
    recent = ctx.recent_decision("package_delivered", hours=ctx.config.package_at_risk_hours)
    if recent is None or (ctx.visit is not None and ctx.visit.package):
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "package_at_risk",
        "A person approached while a package was waiting.",
        f"Someone is at {ctx.where} and a package was delivered earlier. Worth a look.",
        actions=ctx.actions("view_live"),
        confidence=0.6,
        key=ctx.visit_key,
    )


def night_presence(ctx: RuleContext) -> Decision | None:
    if not ctx.quiet:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.MEDIUM,
        "night_presence",
        "Person at the door during quiet hours.",
        f"Someone is at {ctx.where} at {ctx.when}.",
        actions=ctx.actions("view_live", "call_family"),
        confidence=0.7,
        key=ctx.visit_key,
    )


def unusual_time(ctx: RuleContext) -> Decision | None:
    if ctx.anomaly < ctx.config.anomaly_notify_threshold:
        return None
    return ctx.decide(
        Action.NOTIFY,
        Severity.LOW,
        "unusual_time",
        "Person at the door at an unusual time for this home.",
        f"Someone is at {ctx.where} at {ctx.when}, which is unusual for this time.",
        actions=ctx.actions("view_live", "mark_expected"),
        confidence=0.55,
        key=ctx.visit_key,
    )


def routine_presence(ctx: RuleContext) -> Decision | None:
    return ctx.decide(Action.LOG, Severity.INFO, "routine_presence", "Person at the door at a normal time.", f"Someone is at {ctx.where}.")


def home_rules() -> RuleRegistry:
    """A fresh copy of the default home rule set, in evaluation order."""
    reg = RuleRegistry()
    reg.add(sensor_maintenance, kinds={K.SENSOR_ALERT})
    reg.add(sensor_comfort, kinds={K.SENSOR_ALERT})
    reg.add(sensor_alert, kinds={K.SENSOR_ALERT})
    reg.add(sensor_cleared, kinds={K.SENSOR_CLEARED})
    reg.add(device_offline, kinds={K.DEVICE_OFFLINE})
    reg.add(device_online, kinds={K.DEVICE_ONLINE})
    reg.add(account_change, kinds={K.ACCOUNT})
    reg.add(informational, kinds={K.LIVE_VIEW, K.OTHER})
    reg.add(door_closed, kinds={K.DOOR_CLOSED})
    reg.add(expected_entry, kinds={K.DOOR_OPENED})
    reg.add(night_door_open, kinds={K.DOOR_OPENED})
    reg.add(door_open_from_inside, kinds={K.DOOR_OPENED})
    reg.add(door_opened, kinds={K.DOOR_OPENED})
    reg.add(expected_arrival, kinds={K.BUTTON_PRESS})
    reg.add(night_doorbell, kinds={K.BUTTON_PRESS})
    reg.add(lingering_ring, kinds={K.BUTTON_PRESS})
    reg.add(unknown_visitor, kinds={K.BUTTON_PRESS})
    reg.add(package_delivered, kinds={K.MOTION})
    reg.add(non_person_motion, kinds={K.MOTION})
    reg.add(expected_presence, kinds={K.MOTION})
    reg.add(lingering, kinds={K.MOTION})
    reg.add(stepped_outside, kinds={K.MOTION})
    reg.add(package_at_risk, kinds={K.MOTION})
    reg.add(night_presence, kinds={K.MOTION})
    reg.add(unusual_time, kinds={K.MOTION})
    reg.add(routine_presence, kinds={K.MOTION})
    return reg


# ---------------------------------------------------------------------------- sweeps


def close_stale_visits(ctx: SweepContext) -> list[Decision]:
    """Housekeeping: close a visit once the gap has passed. Emits nothing."""
    visit = ctx.store.open_visit(ctx.site.id)
    if visit is not None and ctx.now - visit.last_event_at > timedelta(minutes=ctx.config.visit_gap_min):
        visit.status = VisitStatus.CLOSED
        visit.ended_at = visit.last_event_at
        ctx.store.put_visit(visit)
    return []


def no_show(ctx: SweepContext) -> list[Decision]:
    """An expected visit's window closed with no matching visit."""
    out: list[Decision] = []
    grace = timedelta(minutes=ctx.config.match_grace_min)
    for exp in ctx.store.expected(ctx.site.id):
        for ws, we in exp.windows_between(ctx.now - timedelta(hours=24), ctx.now, ctx.site.zone):
            if we + grace > ctx.now:
                continue
            key = f"{exp.id}:{ws.date().isoformat()}"
            if ctx.already_decided("no_show", key=key, since=ws - timedelta(days=1)):
                continue
            if any(
                v.expected_visit_id == exp.id and ws - grace <= v.started_at <= we + grace
                for v in ctx.store.visits(ctx.site.id, since=ws - grace)
            ):
                continue
            person = ctx.store.get_person(exp.person_id) if exp.person_id else None
            who = person.name if person else exp.label
            out.append(
                ctx.decide(
                    Action.NOTIFY,
                    Severity.MEDIUM,
                    "no_show",
                    f"No visit matched the expected window {ws.astimezone(ctx.site.zone):%a %H:%M}-{we.astimezone(ctx.site.zone):%H:%M}.",
                    f"{who} did not show up for the {ws.astimezone(ctx.site.zone).strftime('%I:%M %p').lstrip('0')} visit.",
                    key=key,
                    expected=exp,
                    actions=[SuggestedAction(kind="call_person", label=f"Call {who}", target_person_id=exp.person_id)]
                    if exp.person_id
                    else [],
                )
            )
    return out


def inactivity(ctx: SweepContext) -> list[Decision]:
    """Nobody at the door for a long time, at a home that normally sees someone daily."""
    if ctx.site.kind is not SiteKind.HOME or not (9 <= ctx.local.hour <= 21):
        return []
    last = ctx.store.get_state(ctx.site.id, "last_presence_at")
    if not last or not (ctx.routine.expects_daily_activity() or ctx.site.metadata.get("expect_daily_activity")):
        return []
    from datetime import datetime

    hours = (ctx.now - datetime.fromisoformat(last)).total_seconds() / 3600
    key = ctx.local.date().isoformat()
    if hours < ctx.config.inactivity_hours or ctx.already_decided("inactivity", key=key, since=ctx.now - timedelta(days=1)):
        return []
    return [
        ctx.decide(
            Action.NOTIFY,
            Severity.MEDIUM,
            "inactivity",
            f"No one has been at the door for {hours:.0f} hours; this home usually has daily activity.",
            f"Nothing has happened at the front door for about {hours:.0f} hours, which is unusual for {ctx.site.name}.",
            key=key,
            confidence=0.6,
            actions=[SuggestedAction(kind="call_resident", label="Check in by phone")],
        )
    ]


def door_left_open(ctx: SweepContext) -> list[Decision]:
    from datetime import datetime

    out: list[Decision] = []
    for key_name, value in ctx.store.states_with_prefix(ctx.site.id, "door_open:").items():
        if not value:
            continue
        opened = datetime.fromisoformat(value)
        minutes = (ctx.now - opened).total_seconds() / 60
        device_id = key_name.split(":", 1)[1]
        if minutes < ctx.config.door_open_notify_min or ctx.already_decided("door_left_open", key=device_id, since=opened):
            continue
        out.append(
            ctx.decide(
                Action.NOTIFY,
                Severity.LOW,
                "door_left_open",
                f"Contact sensor has reported open for {minutes:.0f} minutes.",
                f"The door has been open for about {minutes:.0f} minutes.",
                key=device_id,
                confidence=0.8,
            )
        )
    return out


def home_sweeps() -> SweepRegistry:
    reg = SweepRegistry()
    reg.add(close_stale_visits)
    reg.add(no_show)
    reg.add(inactivity)
    reg.add(door_left_open)
    return reg


def _reading_text(ctx: RuleContext) -> str | None:
    """'88°F' or '71% humidity' when the event carries a polled reading; Fahrenheit for US homes."""
    value = ctx.event.raw.get("reading")
    if value is None:
        return None
    if ctx.event.raw.get("unit") == "C":
        default_units = "F" if ctx.site.timezone.startswith("America/") else "C"
        if ctx.site.metadata.get("units", default_units) == "F":
            return f"{round(value * 9 / 5 + 32)}°F"
        return f"{round(value)}°C"
    if ctx.event.raw.get("unit") == "%":
        return f"{round(value)}% humidity"
    return str(value)
