"""Amazon Bedrock reasoner (Converse API, multimodal when a snapshot is available).

Requires the ``aws`` extra (``pip install "stoop[aws]"``) and normal AWS credentials.
Default model is Amazon Nova 2 Lite; any Converse-capable model id works.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from stoop.memory.models import Severity
from stoop.reasoning.base import Reasoner, ReasoningContext, Refinement

log = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "amazon.nova-2-lite-v1:0"

SYSTEM_PROMPT = """You help a person look after a home or small property by interpreting front-door events.
You receive one event, the rule-based decision already made, context about who is expected, and recent history.
Write for a busy human: plain words, one or two sentences, no device ids, no JSON in the message.
Never identify a person by face. Describe what is visible only in neutral terms (clothing, package, vehicle).
Respond ONLY with a JSON object: {"message": str, "reason": str, "severity": "info"|"low"|"medium"|"high"|null,
"confidence": number 0..1, "observations": [str]}.
Keep severity null unless the context clearly justifies moving it one step."""


class BedrockReasoner(Reasoner):
    name = "bedrock"

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_MODEL_ID,
        region_name: str | None = None,
        client: Any | None = None,
        max_tokens: int = 400,
        temperature: float = 0.2,
    ) -> None:
        if client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - import guard
                raise RuntimeError('BedrockReasoner needs boto3: pip install "stoop[aws]"') from exc
            client = boto3.client("bedrock-runtime", region_name=region_name)
        self._client = client
        self.model_id = model_id
        self.max_tokens = max_tokens
        self.temperature = temperature

    def refine(self, ctx: ReasoningContext) -> Refinement | None:
        content: list[dict[str, Any]] = [{"text": build_prompt(ctx)}]
        if ctx.snapshot:
            content.append({"image": {"format": ctx.snapshot_format, "source": {"bytes": ctx.snapshot}}})
        try:
            resp = self._client.converse(
                modelId=self.model_id,
                system=[{"text": SYSTEM_PROMPT}],
                messages=[{"role": "user", "content": content}],
                inferenceConfig={"maxTokens": self.max_tokens, "temperature": self.temperature},
            )
            text = "".join(part.get("text", "") for part in resp["output"]["message"]["content"])
        except Exception:  # noqa: BLE001 - reasoning is best-effort by design
            log.exception("Bedrock refinement failed; keeping rule-based decision")
            return None
        return parse_refinement(text)


def build_prompt(ctx: ReasoningContext) -> str:
    d, e = ctx.decision, ctx.event
    lines = [
        f"Site: {ctx.site.name} ({ctx.site.kind.value}), local time {ctx.local_time.strftime('%A %H:%M')}.",
        f"Event: {e.kind.value}" + (f" ({e.detected.value})" if e.detected else "") + f" at {e.device_name or 'the door'}.",
        f"Rule decision: action={d.action.value}, severity={d.severity.value}, rule={d.rule}.",
        f"Rule message: {d.message}",
        f"Rule reason: {d.reason}",
    ]
    if ctx.anomaly_score is not None:
        lines.append(f"Anomaly score for this hour: {ctx.anomaly_score:.2f} (1 = never seen at this time).")
    if ctx.matched_expected:
        who = ctx.matched_person.name if ctx.matched_person else ctx.matched_expected.label
        lines.append(f"Matched expected visit: {who} ({ctx.matched_expected.label}).")
    else:
        lines.append("No expected visit matches this time.")
    if ctx.visit:
        lines.append(
            f"Current visit: {ctx.visit.presence_count} presence events, rang={ctx.visit.rang}, "
            f"door_opened={ctx.visit.door_opened}, package={ctx.visit.package}."
        )
    if ctx.known_people:
        lines.append("Known people: " + ", ".join(f"{p.name} ({p.role.value})" for p in ctx.known_people[:8]) + ".")
    if ctx.recent_decisions:
        lines.append("Recent decisions (newest first):")
        for r in ctx.recent_decisions[:6]:
            lines.append(f"  - {r.created_at.astimezone(ctx.site.zone).strftime('%a %H:%M')} {r.action.value}/{r.severity.value}: {r.message}")
    if ctx.snapshot:
        lines.append("A snapshot from the camera at the moment of the event is attached.")
    lines.append("Return the JSON object now.")
    return "\n".join(lines)


def parse_refinement(text: str) -> Refinement | None:
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not data.get("message"):
        return None
    sev = data.get("severity")
    if sev is not None:
        try:
            data["severity"] = Severity(str(sev).lower())
        except ValueError:
            data["severity"] = None
    try:
        return Refinement.model_validate(data)
    except Exception:  # noqa: BLE001
        return None
