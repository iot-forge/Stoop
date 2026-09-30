from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from ring_sandbox import webhooks as rs_webhooks
from ring_sandbox.emulator import create_app
from ring_sandbox.pytest_plugin import _SyncASGITransport
from ring_sandbox.world import default_world

from stoop.events import Detected, EventKind
from stoop.sources.ring import RingHistory, RingSignatureError, parse_ring_webhook

KEY = "test-signing-key"


def _signed(event_type: str, **kw) -> tuple[bytes, str]:
    payload = rs_webhooks.build_event(event_type=event_type, device_id="ava1.ring.device.ABC", **kw)
    body = rs_webhooks.encode(payload)
    return body, rs_webhooks.sign(KEY, body)


def test_motion_webhook_maps_to_event():
    at = datetime(2026, 9, 21, 13, 5, tzinfo=UTC)
    body, sig = _signed("motion_detected", sub_type="human", occurred_at=at)
    ev = parse_ring_webhook(body, site_id="home-1", signing_key=KEY, signature=sig, device_names={"ava1.ring.device.ABC": "Front Door"})
    assert ev.kind is EventKind.MOTION
    assert ev.detected is Detected.HUMAN
    assert ev.device_name == "Front Door"
    assert ev.occurred_at == at
    assert ev.source == "ring"
    assert ev.media and ev.media[0].kind == "snapshot"
    assert ev.dedupe_key  # request_id


def test_button_and_sensor_mapping():
    body, sig = _signed("button_press")
    assert parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig).kind is EventKind.BUTTON_PRESS
    body, sig = _signed("contact_sensor_faulted")
    ev = parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig)
    assert ev.kind is EventKind.DOOR_OPENED and ev.sensor == "contact"
    body, sig = _signed("flood_detected")
    ev = parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig)
    assert ev.kind is EventKind.SENSOR_ALERT and ev.sensor == "flood"
    body, sig = _signed("device_offline")
    assert parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig).kind is EventKind.DEVICE_OFFLINE


def test_bad_signature_rejected():
    body, _ = _signed("button_press")
    with pytest.raises(RingSignatureError):
        parse_ring_webhook(body, site_id="s", signing_key=KEY, signature="sha256=deadbeef")
    with pytest.raises(RingSignatureError):
        parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=None)


def test_same_delivery_twice_yields_same_id():
    body, sig = _signed("button_press")
    a = parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig)
    b = parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig)
    assert a.id == b.id


def test_history_import_from_emulator():
    world = default_world()
    transport = _SyncASGITransport(create_app(world))
    doorbell = world.cameras()[0]
    now = datetime.now(tz=UTC)
    with httpx.Client(base_url="http://sandbox", transport=transport) as ctl:
        for i, (etype, sub) in enumerate([("motion_detected", "human"), ("button_press", None), ("motion_detected", "vehicle")]):
            r = ctl.post(
                "/_sandbox/events",
                json={
                    "device_id": doorbell.id,
                    "type": etype,
                    "sub_type": sub,
                    "at": (now - timedelta(minutes=30 - i)).isoformat(),
                    "deliver": False,
                },
            )
            r.raise_for_status()

    with RingHistory("sandbox-token", base_url="http://sandbox", transport=transport) as ring:
        devices = ring.devices()
        assert any(d["id"] == doorbell.id and d["name"] == "Front Door" for d in devices)
        events = ring.events("home-1", doorbell.id, device_name="Front Door", since=now - timedelta(hours=1))

    kinds = [e.kind for e in events]
    assert kinds == [EventKind.MOTION, EventKind.BUTTON_PRESS, EventKind.MOTION]
    # Documented history shape carries no sub_type; classification only arrives via webhooks.
    assert events[0].detected is Detected.UNKNOWN
    assert events[0].occurred_at < events[1].occurred_at
    assert all(e.source == "ring" for e in events)


def test_history_follows_url_encoded_cursor_and_stops_on_empty_pages():
    """Real Ring: links.next is URL-encoded, and pages can be empty while the cursor moves back."""
    from stoop.sources.ring import next_page_key

    assert (
        next_page_key("/v1/history/devices/X/events?page%5Blimit%5D=5&page%5Bkey%5D=2026-09-28T23%3A12%3A58.054Z")
        == "2026-09-28T23:12:58.054Z"
    )
    assert next_page_key("/v1/x?page[key]=abc&y=1") == "abc"
    assert next_page_key(None) is None and next_page_key("/v1/x?y=1") is None

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(request.url.params))
        n = len(calls)
        # One real event, then Ring keeps paging back with empty pages.
        data = [{"type": "history-events", "id": "e1", "attributes": {"event_type": "ding", "start": 1790000000000}}] if n == 1 else []
        return httpx.Response(
            200, json={"data": data, "links": {"next": f"/v1/history/devices/D/events?page%5Bkey%5D=2026-09-{28 - n:02d}T00%3A00%3A00Z"}}
        )

    with RingHistory("t", base_url="http://ring", transport=httpx.MockTransport(handler)) as ring:
        events = ring.events("home", "D")
    assert [e.kind for e in events] == [EventKind.BUTTON_PRESS]
    assert calls[1]["page[key]"] == "2026-09-27T00:00:00Z"  # decoded cursor was sent back
    assert len(calls) == 4  # 1 page with data + 3 empty, then stop


def test_account_events_are_not_door_activity():
    from stoop import Action, PolicyEngine, Store

    for etype in ("app_integration_added", "device_added", "device_removed", "subscription_deactivated"):
        body, sig = _signed(etype)
        ev = parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig, device_names={"ava1.ring.device.ABC": "Front Door"})
        assert ev.kind is EventKind.ACCOUNT and ev.sensor == etype
    engine = PolicyEngine(Store(":memory:"))
    body, sig = _signed("device_added")
    d = engine.handle(
        parse_ring_webhook(body, site_id="s", signing_key=KEY, signature=sig, device_names={"ava1.ring.device.ABC": "Front Door"})
    )
    assert d.rule == "account_change" and d.action is Action.IGNORE and d.visit_id is None
    assert d.message == "Front Door was shared with this app."
