"""stoop: turn front-door events into decisions a person can act on.

Ingest events from Ring (or anything else), remember who is expected and what is normal,
decide whether to ignore, log, notify or escalate, and keep every sensitive action behind
a human confirmation.
"""

from stoop.events import Detected, Event, EventKind, MediaRef
from stoop.memory import (
    Action,
    Decision,
    ExpectedVisit,
    Person,
    Role,
    Severity,
    Site,
    SiteKind,
    Store,
    SuggestedAction,
    Visit,
)
from stoop.pipeline import CallbackSink, LogSink, Pipeline, Sink
from stoop.policy import PolicyConfig, PolicyEngine, RoutineModel
from stoop.reasoning import DeterministicReasoner, Reasoner, ReasoningContext, Refinement

__version__ = "0.1.1"

__all__ = [
    "Action",
    "CallbackSink",
    "Decision",
    "Detected",
    "DeterministicReasoner",
    "Event",
    "EventKind",
    "ExpectedVisit",
    "LogSink",
    "MediaRef",
    "Person",
    "Pipeline",
    "PolicyConfig",
    "PolicyEngine",
    "Reasoner",
    "ReasoningContext",
    "Refinement",
    "Role",
    "RoutineModel",
    "Severity",
    "Sink",
    "Site",
    "SiteKind",
    "Store",
    "SuggestedAction",
    "Visit",
]
