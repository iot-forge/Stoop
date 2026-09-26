"""Ring Partner API adapter.

Two entry points:

* :func:`parse_ring_webhook` verifies the ``X-Signature`` HMAC over the raw body and maps a
  v1.1 webhook payload to an :class:`~stoop.events.Event`.
* :class:`RingHistory` pulls device lists and paginated event history over HTTPS
  (``https://api.amazonvision.com`` in production, or a local emulator such as
  ``ring-sandbox`` during development).

Only ``httpx`` is required. Shapes follow
https://developer.amazon.com/docs/ring/api-documentation.html.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from stoop.events import Detected, Event, EventKind, MediaRef, make_event_id

SOURCE = "ring"
SIGNATURE_HEADER = "X-Signature"
DEFAULT_BASE_URL = "https://api.amazonvision.com"

_SENSOR_ALERTS = {
    "tamper_detected": "tamper",
    "flood_detected": "flood",
    "freeze_detected": "freeze",
    "temperature_exceeded": "temperature",
    "humidity_exceeded": "humidity",
    "pm25_exceeded": "pm25",
    "co_exceeded": "co",
}
_SENSOR_CLEARS = {
    "tamper_cleared": "tamper",
    "flood_cleared": "flood",
    "freeze_cleared": "freeze",
    "temperature_cleared": "temperature",
    "humidity_cleared": "humidity",
    "pm25_cleared": "pm25",
    "co_cleared": "co",
}
_DETECTED = {
    "human": Detected.HUMAN,
    "vehicle": Detected.VEHICLE,
    "animal": Detected.ANIMAL,
    "package": Detected.PACKAGE,
    "motion": Detected.MOTION,
    "other_motion": Detected.MOTION,
}


class RingSignatureError(ValueError):
    """Raised when a webhook body does not match its ``X-Signature`` header."""


def sign_ring_body(signing_key: str, raw_body: bytes) -> str:
    return "sha256=" + hmac.new(signing_key.encode(), raw_body, hashlib.sha256).hexdigest()


def verify_ring_signature(signing_key: str, raw_body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    expected = sign_ring_body(signing_key, raw_body)
    return hmac.compare_digest(expected.encode("ascii"), signature.strip().encode("ascii", "ignore"))


def _map_webhook_kind(event_type: str) -> tuple[EventKind, str | None]:
    if event_type == "motion_detected":
        return EventKind.MOTION, None
    if event_type == "button_press":
        return EventKind.BUTTON_PRESS, None
    if event_type == "contact_sensor_faulted":
        return EventKind.DOOR_OPENED, "contact"
    if event_type == "contact_sensor_cleared":
        return EventKind.DOOR_CLOSED, "contact"
    if event_type == "device_online":
        return EventKind.DEVICE_ONLINE, None
    if event_type == "device_offline":
        return EventKind.DEVICE_OFFLINE, None
    if event_type in _SENSOR_ALERTS:
        return EventKind.SENSOR_ALERT, _SENSOR_ALERTS[event_type]
    if event_type in _SENSOR_CLEARS:
        return EventKind.SENSOR_CLEARED, _SENSOR_CLEARS[event_type]
    return EventKind.OTHER, None


def parse_ring_webhook(
    raw_body: bytes,
    *,
    site_id: str,
    signing_key: str | None = None,
    signature: str | None = None,
    device_names: dict[str, str] | None = None,
) -> Event:
    """Verify (when ``signing_key`` is given) and normalize one Ring webhook delivery.

    Verification always runs over the raw bytes, never over re-serialized JSON.
    """
    if signing_key is not None and not verify_ring_signature(signing_key, raw_body, signature):
        raise RingSignatureError("Ring webhook signature mismatch")

    payload = json.loads(raw_body)
    meta = payload.get("meta", {})
    data = payload.get("data", {})
    attrs = data.get("attributes", {})
    event_type = data.get("type", "unknown")
    device_id = attrs.get("source") or attrs.get("device_id") or "unknown"

    ts = attrs.get("timestamp")
    if isinstance(ts, (int, float)):
        occurred_at = datetime.fromtimestamp(ts / 1000, tz=UTC)
    else:
        occurred_at = _parse_iso(meta.get("time")) or datetime.now(tz=UTC)

    kind, sensor = _map_webhook_kind(event_type)
    detected = _DETECTED.get(str(attrs.get("sub_type") or "").lower()) if kind is EventKind.MOTION else None
    if kind is EventKind.MOTION and detected is None:
        detected = Detected.UNKNOWN

    dedupe_key = meta.get("request_id") or data.get("id") or f"{device_id}:{event_type}:{occurred_at.isoformat()}"
    media: list[MediaRef] = []
    if kind in (EventKind.MOTION, EventKind.BUTTON_PRESS):
        media.append(MediaRef(kind="snapshot", device_id=device_id, at=occurred_at))

    return Event(
        id=make_event_id(SOURCE, dedupe_key),
        site_id=site_id,
        source=SOURCE,
        kind=kind,
        detected=detected,
        device_id=device_id,
        device_name=(device_names or {}).get(device_id),
        occurred_at=occurred_at,
        sensor=sensor,
        media=media,
        dedupe_key=dedupe_key,
        raw=payload,
    )


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class RingHistory:
    """Minimal synchronous client for device discovery and event history.

    ``token`` is a Playground token (30 minutes) or an OAuth access token. Pass a custom
    ``base_url`` to talk to an emulator. The optional ``transport`` is for tests.
    """

    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> RingHistory:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._http.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    def devices(self) -> list[dict[str, Any]]:
        """Return ``[{"id", "name", "online"}, ...]`` for every accessible device."""
        doc = self._get("/v1/devices", params={"include": "status"})
        status_by_id: dict[str, bool | None] = {}
        for inc in doc.get("included", []) or []:
            if inc.get("type") == "device-status":
                dev_id = str(inc.get("id", "")).split(".status")[0]
                status_by_id[dev_id] = inc.get("attributes", {}).get("online")
        out = []
        for d in doc.get("data", []):
            out.append(
                {
                    "id": d["id"],
                    "name": d.get("attributes", {}).get("name") or d["id"],
                    "online": status_by_id.get(d["id"]),
                }
            )
        return out

    def snapshot(
        self,
        device_id: str,
        *,
        start: datetime,
        end: datetime | None = None,
        fmt: str = "jpeg",
    ) -> bytes | None:
        """Latest snapshot in a time range, following Ring's redirect to the media URL.

        Returns ``None`` when no image exists in range (HTTP 416) or the device is encrypted
        (TAKE devices return unreadable content, which we detect by content type).
        """
        body: dict[str, Any] = {
            "type": "latest_in_range",
            "start_timestamp": int(start.timestamp() * 1000),
            "image_options": {"format": fmt},
        }
        if end is not None:
            body["end_timestamp"] = int(end.timestamp() * 1000)
        resp = self._http.post(
            f"/v1/devices/{device_id}/media/image/download",
            json=body,
            headers={"Accept": "*/*"},
            follow_redirects=True,
        )
        if resp.status_code in (404, 416):
            return None
        resp.raise_for_status()
        if not resp.headers.get("Content-Type", "").startswith("image/"):
            return None
        return resp.content

    def iter_history(
        self,
        device_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        page_size: int = 100,
        max_pages: int = 50,
    ) -> Iterator[dict[str, Any]]:
        """Yield raw ``history-events`` resources, newest first, following ``links.next``."""
        params: dict[str, Any] = {"page[limit]": page_size}
        if since is not None:
            params["filter[start]"] = int(since.timestamp() * 1000)
        if until is not None:
            params["filter[end]"] = int(until.timestamp() * 1000)
        path = f"/v1/history/devices/{device_id}/events"
        for _ in range(max_pages):
            doc = self._get(path, params=params)
            yield from doc.get("data", [])
            nxt = (doc.get("links") or {}).get("next")
            if not nxt or "page[key]=" not in nxt:
                return
            params = {**params, "page[key]": nxt.split("page[key]=", 1)[1].split("&", 1)[0]}

    def events(
        self,
        site_id: str,
        device_id: str,
        *,
        device_name: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[Event]:
        """Fetch history for one device as normalized events (oldest first)."""
        out: list[Event] = []
        for item in self.iter_history(device_id, since=since, until=until):
            ev = history_item_to_event(item, site_id=site_id, device_id=device_id, device_name=device_name)
            if ev is not None:
                out.append(ev)
        out.sort(key=lambda e: e.occurred_at)
        return out


def history_item_to_event(
    item: dict[str, Any], *, site_id: str, device_id: str, device_name: str | None = None
) -> Event | None:
    """Map one ``history-events`` resource to an Event. Unknown types map to OTHER."""
    attrs = item.get("attributes", {})
    event_type = attrs.get("event_type")
    start = attrs.get("start")
    if not isinstance(start, (int, float)):
        return None
    occurred_at = datetime.fromtimestamp(start / 1000, tz=UTC)
    if event_type == "motion":
        kind = EventKind.MOTION
        detected = _DETECTED.get(str(attrs.get("sub_type") or "").lower(), Detected.UNKNOWN)
    elif event_type == "ding":
        kind, detected = EventKind.BUTTON_PRESS, None
    elif event_type == "on_demand":
        kind, detected = EventKind.LIVE_VIEW, None
    else:
        kind, detected = EventKind.OTHER, None
    dedupe_key = f"history:{item.get('id') or f'{device_id}:{start}'}"
    return Event(
        id=make_event_id(SOURCE, dedupe_key),
        site_id=site_id,
        source=SOURCE,
        kind=kind,
        detected=detected,
        device_id=device_id,
        device_name=device_name,
        occurred_at=occurred_at,
        media=[MediaRef(kind="clip", device_id=device_id, at=occurred_at)] if kind is not EventKind.OTHER else [],
        dedupe_key=dedupe_key,
        raw=item,
    )
