from __future__ import annotations

from conftest import local

from stoop import PolicyConfig, PolicyEngine, Severity
from stoop.reasoning.bedrock import BedrockReasoner, build_prompt, parse_refinement
from stoop.sources.synthetic import BUILTIN, play_scenario


class _FakeBedrock:
    def __init__(self, text: str):
        self.text = text
        self.calls: list[dict] = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {"output": {"message": {"content": [{"text": self.text}]}}}


def test_parse_refinement_tolerates_prose_and_fences():
    text = 'Sure:\n```json\n{"message": "Someone in a red jacket rang twice.", "reason": "x", "severity": "HIGH", "confidence": 0.9, "observations": ["red jacket"]}\n```'
    ref = parse_refinement(text)
    assert ref and ref.severity is Severity.HIGH and ref.observations == ["red jacket"]
    assert parse_refinement("no json here") is None
    assert parse_refinement('{"severity": "medium"}') is None  # message required


def test_bedrock_refines_and_caps_severity_step(store, site, people):
    fake = _FakeBedrock('{"message": "A courier left a box and drove off.", "reason": "Vehicle then package.", "severity": "info", "confidence": 0.8}')
    eng = PolicyEngine(store, config=PolicyConfig(refine_always=True), reasoner=BedrockReasoner(client=fake, model_id="test"))
    events = play_scenario(BUILTIN["lingering_stranger"], site_id=site.id, start=local(2026, 9, 22, 23, 30))
    decisions = [d for d in (eng.handle(e) for e in events) if d]
    night = next(d for d in decisions if d.rule == "night_doorbell")
    assert night.refined_by == "bedrock"
    assert night.message == "A courier left a box and drove off."
    # Model asked for "info" from "high"; the engine moves at most one step.
    assert night.severity is Severity.MEDIUM
    assert fake.calls and fake.calls[0]["modelId"] == "test"
    prompt = fake.calls[0]["messages"][0]["content"][0]["text"]
    assert "Rule decision" in prompt and "Known people" in prompt


def test_bedrock_failure_keeps_rule_decision(store, site, people):
    class Boom:
        def converse(self, **kwargs):
            raise RuntimeError("throttled")

    eng = PolicyEngine(store, config=PolicyConfig(refine_always=True), reasoner=BedrockReasoner(client=Boom(), model_id="t"))
    events = play_scenario(BUILTIN["lingering_stranger"], site_id=site.id, start=local(2026, 9, 22, 23, 30))
    decisions = [d for d in (eng.handle(e) for e in events) if d]
    night = next(d for d in decisions if d.rule == "night_doorbell")
    assert night.refined_by is None and night.severity is Severity.HIGH


def test_prompt_mentions_snapshot_when_attached(store, site, people):
    from stoop.memory.models import Action, Decision
    from stoop.reasoning.base import ReasoningContext

    d = Decision(site_id=site.id, event_id="e", action=Action.NOTIFY, severity=Severity.MEDIUM, rule="r", reason="x", message="m")
    ev = play_scenario(BUILTIN["no_show"], site_id=site.id, start=local(2026, 9, 22, 12))[0]
    ctx = ReasoningContext(site=site, event=ev, decision=d, local_time=local(2026, 9, 22, 12), snapshot=b"\xff\xd8")
    assert "snapshot" in build_prompt(ctx).lower()
