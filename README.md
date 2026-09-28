# Stoop

Turn front-door events into decisions a person can act on.

`stoop` is a small Python library that sits between a doorbell or camera feed (Ring today,
anything tomorrow) and the humans who care about what happens at that door. It remembers who
is expected, learns what is normal for that door, decides whether an event should be
ignored, logged, sent as a notification, or escalated, and keeps every sensitive action behind
a human confirmation.

It was built during the [Build, Ship, Shape: Amazon Developer Hackathon](https://amazonappdev2026.devpost.com/)
as the shared core of two products: a caregiving app on the Ring track and a conversational
property concierge on the Alexa+ track. The library is product-agnostic and MIT licensed.

## What it does

```
Ring webhook / history ──┐
Synthetic scenarios ─────┼─▶ Event ─▶ Store (SQLite) ─▶ PolicyEngine ─▶ Decision ─▶ Sinks
Your own source ─────────┘                 ▲  ▲                 │
                                           │  └── RoutineModel ─┘   (what is normal here?)
                                           └───── ExpectedVisit / Person   (who is expected?)
```

- **Events** (`stoop.events`): one normalized shape for motion, doorbell presses, door
  sensors, device health and environmental sensors. Ring's `X-Signature` HMAC is verified
  over the raw body.
- **Memory** (`stoop.memory`): sites, people and their roles, expected visits (one-off or
  recurring), visits (events clustered into "someone came to the door"), decisions, and a
  small key/value state. SQLite, standard library only.
- **Routines** (`stoop.policy.routines`): weekly rates per weekday and hour, an anomaly
  score for "how surprising is this right now", and "does this door usually see someone
  every day".
- **Policy** (`stoop.policy.engine`): deterministic rules that always produce a complete
  decision, plus a sweep for things that did not happen: no-shows, inactivity, doors left
  open. Notifications about the same visit are suppressed so one visitor is one alert.
- **Reasoning** (`stoop.reasoning`): an optional refinement step. The deterministic reasoner
  adds context with no model call. The Bedrock reasoner uses the Converse API (Amazon Nova 2
  Lite by default, multimodal when a snapshot is available). A reasoner can reword and move
  severity by one step, and can never remove a confirmation requirement.
- **Pipeline** (`stoop.pipeline`): source → engine → sinks, with backfill for routine learning.

Reasoning runs on the ingestion path only. Anything that answers a question (a dashboard, an
MCP tool for Alexa+) reads precomputed state and stays fast.

## Install

```bash
pip install stoop            # core
pip install "stoop[aws]"     # + boto3 for the Bedrock reasoner
```

Python 3.13 or newer.

## Quick start

```python
from datetime import UTC, datetime, time

from stoop import ExpectedVisit, Person, Pipeline, PolicyEngine, Role, Site, Store, LogSink
from stoop.sources.synthetic import BUILTIN, generate_baseline, play_scenario

store = Store("stoop.db")
site = store.put_site(Site(id="moms-house", name="Mom's house", timezone="America/New_York"))
maria = store.put_person(Person(site_id=site.id, name="Maria", role=Role.AIDE))
store.put_expected(ExpectedVisit(site_id=site.id, label="Morning aide", person_id=maria.id,
                                 days_of_week=[0, 2, 4], local_start=time(9, 0), local_end=time(10, 30)))

pipeline = Pipeline(PolicyEngine(store), sinks=[LogSink()])

# Teach it what "normal" looks like (synthetic here; real history from RingHistory in production).
now = datetime.now(tz=UTC)
pipeline.backfill(generate_baseline(site_id=site.id, days=28, end=now))

# Live events.
for decision in pipeline.ingest_many(play_scenario(BUILTIN["lingering_stranger"], site_id=site.id, start=now)):
    print(decision.action, decision.severity, decision.message)

# Periodic checks for what did not happen.
pipeline.sweep()
```

### Ring webhooks

```python
from stoop.sources.ring import parse_ring_webhook, RingSignatureError

@app.post("/webhooks/ring")
async def ring_webhook(request):
    body = await request.body()
    try:
        event = parse_ring_webhook(body, site_id=site_id_for(request), signing_key=RING_HMAC_KEY,
                                   signature=request.headers.get("X-Signature"))
    except RingSignatureError:
        return Response(status_code=401)
    pipeline.ingest(event)
    return Response(status_code=200)
```

### Ring account linking

Ring links accounts two ways. The default, **one-way** flow starts in the Ring Appstore: Ring
posts an authorization code to your Token Exchange URL, then sends the user's browser to your
Account Link URL with a `nonce` and `time`. `RingLinker` handles both halves and the
**partner-initiated** PKCE flow, and keeps tokens fresh.

```python
from stoop import Store
from stoop.sources.ring_oauth import RingLinker, RingOAuth, RingOAuthConfig, SqliteTokenStore

oauth = RingOAuth(RingOAuthConfig(client_id=..., client_secret=..., hmac_key=...))
linker = RingLinker(oauth, SqliteTokenStore(store, cipher=Fernet(key)))   # any encrypt/decrypt pair

# Token Exchange URL (server to server): park the tokens, look up the Ring account id.
link_id = linker.receive_code(code)

# Account Link URL (browser, after your own sign-in): prove which parked token is this user's.
link_id = linker.claim_by_nonce(nonce=nonce, time_value=time, owner=user.id)

# Later: a valid access token, refreshed and persisted when needed.
with RingHistory(linker.access_token(link_id)) as ring: ...
```

### Ring history backfill

```python
from stoop.sources.ring import RingHistory

with RingHistory(token) as ring:                       # Playground token or OAuth access token
    for device in ring.devices():
        pipeline.backfill(ring.events(site.id, device["id"], device_name=device["name"]))
```

Documented Ring history carries no person/vehicle/package classification. Only webhooks do,
so backfilled motion is stored as `detected=unknown`.

### Bedrock reasoning

```python
from stoop import PolicyConfig, PolicyEngine
from stoop.reasoning.bedrock import BedrockReasoner

engine = PolicyEngine(store, config=PolicyConfig(refine_min_severity="medium"),
                      reasoner=BedrockReasoner(region_name="us-east-1"),
                      snapshot_fetcher=fetch_ring_snapshot)   # optional: bytes for multimodal context
```

## Custom rules

Rules live in an ordered registry. The first rule that returns a decision wins, so specific
rules go before general ones. `home_rules()` returns a fresh copy of the default set; add,
move, replace or disable without forking:

```python
from stoop import Action, Decision, EventKind, PolicyEngine, Severity, SiteKind
from stoop.policy import RuleContext, home_rules, home_sweeps

rules = home_rules()

@rules.add(before="unknown_visitor", kinds={EventKind.BUTTON_PRESS})
def lunch_courier(ctx: RuleContext) -> Decision | None:
    """Weekday lunch doorbells at an office are couriers, not strangers."""
    if 11 <= ctx.local.hour < 14 and ctx.site.kind is SiteKind.OFFICE:
        return ctx.decide(Action.LOG, Severity.INFO, "lunch_courier", "Lunch delivery window.", f"Lunch delivery at {ctx.where}.")
    return None

rules.disable("package_at_risk")

engine = PolicyEngine(store, rules=rules, sweeps=home_sweeps())
print(rules.names())   # evaluation order
```

`RuleContext` gives a rule the event, site, current visit, matched expected visit, anomaly
score, quiet-hours flag, known people, and builders: `ctx.decide(...)`, `ctx.actions(...)`,
`ctx.recent_decision(...)`. Sweep checks work the same way through `SweepRegistry` and
`SweepContext`, and every default rule is a plain function in `stoop.policy.home_rules` you
can import and reuse.

## Decisions

Every decision carries `action` (ignore, log, notify, escalate), `severity` (info, low,
medium, high), the `rule` that fired, a human-readable `message` and `reason`, an
`anomaly_score`, `suggested_actions` (some marked `sensitive`), and
`requires_confirmation`, which is true whenever any suggested action is sensitive.

Rules today: `expected_arrival`, `expected_entry`, `unknown_visitor`, `night_doorbell`,
`night_presence`, `night_door_open`, `lingering`, `package_delivered`, `package_at_risk`,
`unusual_time`, `sensor_alert`, `device_offline`, `no_show`, `inactivity`, `door_left_open`,
plus quiet `log`/`ignore` outcomes for routine motion.

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check src tests
```

Integration tests use the community [`ring-sandbox`](https://github.com/josepha-mayo/ring-sandbox)
emulator in-process, so no Ring account is needed to run them.

## Docs

- [`docs/roadmap.md`](docs/roadmap.md): what is reusable today, what is not yet, and what is
  planned (OAuth token client, rule registry, FastAPI router, PyPI release).
- [`docs/friction-log.md`](docs/friction-log.md): platform obstacles met while building on
  Ring, Alexa+ and AWS, and the workarounds.

## License

MIT. See `LICENSE`.
