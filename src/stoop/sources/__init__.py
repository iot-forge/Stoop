"""Event sources: adapters that turn vendor payloads into :class:`stoop.events.Event`."""

from stoop.sources.ring import RingHistory, RingSignatureError, parse_ring_webhook
from stoop.sources.synthetic import Scenario, Step, generate_baseline, play_scenario

__all__ = [
    "RingHistory",
    "RingSignatureError",
    "Scenario",
    "Step",
    "generate_baseline",
    "parse_ring_webhook",
    "play_scenario",
]
