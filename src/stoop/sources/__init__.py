"""Event sources: adapters that turn vendor payloads into :class:`stoop.events.Event`."""

from stoop.sources.ring import ComfortThresholds, DeviceStatus, RingHistory, RingSignatureError, parse_ring_webhook, status_events
from stoop.sources.synthetic import Scenario, Step, generate_baseline, play_scenario

__all__ = [
    "ComfortThresholds",
    "DeviceStatus",
    "status_events",
    "RingHistory",
    "RingSignatureError",
    "Scenario",
    "Step",
    "generate_baseline",
    "parse_ring_webhook",
    "play_scenario",
]
