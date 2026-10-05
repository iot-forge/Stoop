"""Polled sensor readings: Ring's device status endpoint -> events on threshold crossings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from conftest import local

from stoop import EventKind, PolicyEngine
from stoop.sources.ring import ComfortThresholds, DeviceStatus, RingHistory, status_events

KITCHEN = "ava1.ring.device.KITCHEN"


def _status_doc(temp: float, hum: float, state=None, at="2026-10-03T04:21:34.320Z") -> dict:
    return {
        "data": {
            "type": "device-status",
            "id": f"{KITCHEN}.status",
            "attributes": {
                "reported_at": at,
                "battery_status": {"percentage": 100},
                "temperature": temp,
                "humidity": hum,
                "online": True,
                "signal_strength": {"value": "good"},
                "state": state,
            },
        },
        "meta": {"time": at},
    }


def test_device_status_parses_rings_shape():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == f"/v1/devices/{KITCHEN}/status" and req.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json=_status_doc(25.4, 56.1))

    with RingHistory("tok", base_url="http://ring", transport=httpx.MockTransport(handler)) as ring:
        st = ring.device_status(KITCHEN)
    assert st.temperature_c == 25.4 and st.humidity == 56.1 and st.battery_pct == 100 and st.online is True and st.state is None
    assert st.reported_at == datetime(2026, 10, 3, 4, 21, 34, 320000, tzinfo=UTC) and st.signal == "good"


def test_crossing_a_threshold_is_one_alert_until_it_clears():
    t = ComfortThresholds()  # 16-29 C, humidity under 70
    at = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)

    def poll(temp, hum, prev, minutes):
        st = DeviceStatus(device_id=KITCHEN, reported_at=at + timedelta(minutes=minutes), temperature_c=temp, humidity=hum)
        return status_events(st, site_id="s", device_name="Kitchen", previous=prev, thresholds=t)

    ev, flags = poll(25.0, 55.0, None, 0)
    assert ev == [] and flags["temperature"] is None and flags["humidity"] is None
    ev, flags = poll(31.0, 55.0, flags, 5)  # too warm
    assert [e.kind for e in ev] == [EventKind.SENSOR_ALERT] and ev[0].sensor == "temperature"
    assert (
        ev[0].raw == {"polled": True, "reading": 31.0, "unit": "C", "direction": "high", "threshold": 29.0}
        and ev[0].device_name == "Kitchen"
    )
    ev, flags = poll(32.0, 55.0, flags, 10)  # still warm: silence
    assert ev == []
    ev, flags = poll(27.0, 75.0, flags, 15)  # cooled down, now damp
    kinds = sorted((e.kind.value, e.sensor) for e in ev)
    assert kinds == [("sensor_alert", "humidity"), ("sensor_cleared", "temperature")]
    ev, flags = poll(27.0, 60.0, flags, 20)
    assert [(e.kind, e.sensor) for e in ev] == [(EventKind.SENSOR_CLEARED, "humidity")]
    # Dedupe keys are stable for a given reading time, so a re-poll of the same report never duplicates.
    a, _ = poll(31.0, 55.0, flags, 25)
    b, _ = poll(31.0, 55.0, flags, 25)
    assert a[0].id == b[0].id


def test_contact_state_flip_becomes_door_events():
    at = datetime(2026, 10, 3, 2, 14, tzinfo=UTC)
    first = DeviceStatus(device_id="d", reported_at=at, state="closed")
    ev, flags = status_events(first, site_id="s", device_name="Front Door", previous=None)
    assert ev == [] and flags["open"] is False  # first poll only records the state
    opened = DeviceStatus(device_id="d", reported_at=at + timedelta(minutes=5), state="open")
    ev, flags = status_events(opened, site_id="s", device_name="Front Door", previous=flags)
    assert [e.kind for e in ev] == [EventKind.DOOR_OPENED] and ev[0].sensor == "contact" and flags["open"] is True
    ev, _ = status_events(opened, site_id="s", device_name="Front Door", previous=flags)
    assert ev == []


def test_comfort_alert_says_the_reading_in_fahrenheit_for_us_homes(store, site):
    eng = PolicyEngine(store)
    st = DeviceStatus(device_id=KITCHEN, reported_at=local(2026, 10, 3, 14, 0), temperature_c=31.0, humidity=50.0)
    ev, _ = status_events(st, site_id=site.id, device_name="Kitchen", previous={"temperature": None})
    d = eng.handle(ev[0])
    assert d is not None and d.rule == "sensor_comfort" and d.message == "Kitchen is 88°F. That is warm for this home."


def test_contact_sensor_status_uses_rings_real_shape():
    doc = {
        "data": {
            "type": "device-status",
            "id": "x.status",
            "attributes": {
                "battery_status": {"percentage": 100},
                "signal_strength": {"value": "good"},
                "tamper_detection": {"detected": False},
                "sensor_reporting_state": {"value": "active"},
                "contact_detection": {"faulted": True},
                "state": None,
                "online": True,
                "reported_at": "2026-10-04T00:13:45.076Z",
            },
        }
    }
    with RingHistory("tok", base_url="http://ring", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc))) as ring:
        st = ring.device_status("ava1.ring.device.BACK")
    assert st.state == "open" and st.tampered is False and st.temperature_c is None
    ev, flags = status_events(st, site_id="s", device_name="Backyard", previous={"open": False, "tampered": False})
    assert [e.kind for e in ev] == [EventKind.DOOR_OPENED] and flags["open"] is True
    doc["data"]["attributes"]["tamper_detection"]["detected"] = True
    with RingHistory("tok", base_url="http://ring", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc))) as ring:
        st = ring.device_status("ava1.ring.device.BACK")
    ev, _ = status_events(st, site_id="s", device_name="Backyard", previous=flags)
    assert [(e.kind, e.sensor) for e in ev] == [(EventKind.SENSOR_ALERT, "tamper")]


def test_live_view_relays_the_offer_and_closes_the_session():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, req.headers.get("Content-Type"), req.content.decode()))
        if req.method == "POST":
            return httpx.Response(200, json={"data": {"type": "whep-session", "id": "sess-1", "attributes": {"answer": "v=0\r\nanswer"}}})
        return httpx.Response(410)

    with RingHistory("tok", base_url="http://ring", transport=httpx.MockTransport(handler)) as ring:
        live = ring.start_live("cam", "v=0\r\noffer")
        assert live.session_id == "sess-1" and live.answer.startswith("v=0") and live.device_id == "cam"
        ring.stop_live("cam", live.session_id)  # already gone on Ring's side: fine
    assert calls[0] == ("POST", "/v1/devices/cam/media/streaming/whep/sessions", "application/sdp", "v=0\r\noffer")
    assert calls[1][:2] == ("DELETE", "/v1/devices/cam/media/streaming/whep/sessions/sess-1")

    # Plain WHEP shape: SDP body, session id in Location.
    plain = httpx.MockTransport(
        lambda r: httpx.Response(
            201,
            content=b"v=0\r\nplain",
            headers={"Content-Type": "application/sdp", "Location": "/v1/devices/cam/media/streaming/whep/sessions/sess-2"},
        )
    )
    with RingHistory("tok", base_url="http://ring", transport=plain) as ring:
        live = ring.start_live("cam", "v=0\r\noffer")
    assert live.session_id == "sess-2" and live.answer == "v=0\r\nplain"
