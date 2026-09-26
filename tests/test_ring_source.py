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
                json={"device_id": doorbell.id, "type": etype, "sub_type": sub, "at": (now - timedelta(minutes=30 - i)).isoformat(), "deliver": False},
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
