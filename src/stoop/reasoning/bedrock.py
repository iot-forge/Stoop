"""Amazon Bedrock reasoner (Converse API, multimodal when a snapshot is available).

Requires the ``aws`` extra (``pip install "stoop[aws]"``) and normal AWS credentials.
Default model is Amazon Nova 2 Lite through its US cross-region inference profile (the plain
model id is rejected for on-demand calls); any Converse-capable model or profile id works.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from stoop.memory.models import Severity
from stoop.reasoning.base import Reasoner, ReasoningContext, Refinement

log = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "us.amazon.nova-2-lite-v1:0"

SYSTEM_PROMPT = """You write the text of one front-door notification for a person looking after a place.
You receive one event, the rule-based decision already made, who is expected, and recent history.

Rules for the message:
- One or two short sentences, under 35 words. Plain words a tired person reads in two seconds.
- Say what happened, when, and why it matters for this reader. Use only facts given to you; never invent
  a link between events, a person, a vehicle or a motive.
- Calm, factual tone. Never use words like intruder, break-in, burglar or danger unless the rule says so.
- At most one suggested action, and only if it is specific ("call her", "check the side door camera").
- Say only what a camera can know. "Movement near the front door" is a fact; "waiting to be let in"
  or "trying to get in" is a guess, so never say it unless the rule says someone rang.
- Never guess a name, relationship or gender. Use the resident's name only if it is given; otherwise say
  "your family member" (home) or "the guest" (rental).
- No device ids, no JSON, no rule names. Refer to cameras by their plain name ("the front door").
- Never identify a person by face. Describe what is visible only in neutral terms (clothing, package, vehicle).

Respond ONLY with a JSON object: {"message": str, "reason": str, "severity": "info"|"low"|"medium"|"high"|null,
"confidence": number 0..1, "observations": [str]}. "reason" is one short clause for the log.
Keep severity null unless the context clearly justifies moving it one step."""

# Who reads the alert changes what matters: a door opening at 2 AM means "Mom may have gone out"
# at a parent's home, and "a guest is up late" at a rental.
AUDIENCE = {
    "home": (
        "The place is the home of an older adult who lives alone. The reader is a family caregiver who lives elsewhere. "
        "What matters: their safety and routine (going out at night, unexpected visitors, missed or late helpers), "
        "not property crime."
    ),
    "rental": "The place is a short-term rental. The reader is the host. What matters: guests, cleaners and contractors arriving as planned.",
    "office": "The place is a small office. The reader runs the front desk. What matters: expected visitors and after-hours activity.",
    "clinic": "The place is a small clinic. The reader runs the front desk. What matters: patients and deliveries arriving as planned.",
}

MAX_MESSAGE_CHARS = 320


class BedrockReasoner(Reasoner):
    name = "bedrock"

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_MODEL_ID,
        region_name: str | None = None,
        client: Any | None = None,
        max_tokens: int = 300,
        temperature: float = 0.2,
        timeout_s: float = 6.0,
        fallback: Reasoner | None = None,
    ) -> None:
        if client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:  # pragma: no cover - import guard
                raise RuntimeError('BedrockReasoner needs boto3: pip install "stoop[aws]"') from exc
            # Alerts must not wait on the model: short timeouts and one retry, then the fallback.
            config = Config(connect_timeout=2, read_timeout=timeout_s, retries={"max_attempts": 1, "mode": "standard"})
            client = boto3.client("bedrock-runtime", region_name=region_name, config=config)
        self._client = client
        self.fallback = fallback
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
        except Exception as exc:  # noqa: BLE001 - reasoning is best-effort by design
            log.warning("Bedrock refinement failed (%s); using fallback", type(exc).__name__)
            return self._fallback(ctx)
        ref = parse_refinement(text)
        if ref is None or len(ref.message) > MAX_MESSAGE_CHARS:
            log.warning("Bedrock reply unusable; using fallback")
            return self._fallback(ctx)
        return ref

    def summarize_day(self, site: Any, items: list[str], *, alerts: int = 0) -> str | None:
        """Two or three sentences over a day's notes, for a digest. None means use the plain list."""
        if not items and not alerts:
            return None
        prompt = "\n".join(
            [
                AUDIENCE.get(site.kind.value, AUDIENCE["home"]),
                *([f"The resident is {site.metadata['resident']}."] if site.metadata.get("resident") else []),
                f"Yesterday at {site.name}: {alerts} alert(s) needed attention. Notes in time order:",
                *(f"- {line}" for line in items[:60]),
                "Write two or three calm sentences, under 60 words, summarizing the day for the reader: the shape of the day, anything",
                "unusual compared with a normal day, and anything to follow up. Use only these facts. Never guess a name,",
                "relationship or gender. No lists, no greeting, no sign-off. Reply with the sentences only.",
            ]
        )
        try:
            resp = self._client.converse(
                modelId=self.model_id,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 200, "temperature": self.temperature},
            )
            text = "".join(part.get("text", "") for part in resp["output"]["message"]["content"]).strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("Bedrock day summary failed (%s)", type(exc).__name__)
            return None
        return text if 0 < len(text) <= 600 and "{" not in text else None

    def _fallback(self, ctx: ReasoningContext) -> Refinement | None:
        if self.fallback is None:
            return None
        ref = self.fallback.refine(ctx)
        return ref.model_copy(update={"by": ref.by or self.fallback.name}) if ref else None


def build_prompt(ctx: ReasoningContext) -> str:
    d, e = ctx.decision, ctx.event
    lines = [
        AUDIENCE.get(ctx.site.kind.value, AUDIENCE["home"]),
        *([f"The resident is {ctx.site.metadata['resident']}."] if ctx.site.metadata.get("resident") else []),
        f"Site: {ctx.site.name}, local time {ctx.local_time.strftime('%A %I:%M %p').replace(' 0', ' ')}.",
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
            lines.append(
                f"  - {r.created_at.astimezone(ctx.site.zone).strftime('%a %H:%M')} {r.action.value}/{r.severity.value}: {r.message}"
            )
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
