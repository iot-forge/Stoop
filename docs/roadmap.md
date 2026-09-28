# Roadmap

What `stoop` is today, what it is not yet, and what would make it genuinely reusable for
other Ring developers. Ordered by value per hour of work.

## Where it stands (v0.1, 2026-09-25)

Reusable today:

- **Ring plumbing Ring does not ship.** Webhook parsing with HMAC verification over the raw
  body, a history client that follows pagination, device discovery, snapshot fetch, and one
  normalized event shape across doorbells, cameras and sensors.
- **The layer every Ring app rebuilds.** Visit clustering, expected-visitor matching (one-off
  and recurring), routine learning with an anomaly score, and an ignore / log / notify /
  escalate decision with suggested actions.
- **An honest AI story.** Rules decide; a model may reword and move severity one step; nothing
  sensitive runs without a human. Bedrock is optional and behind an extra.
- **Testable without accounts.** Runs with no Ring account and no AWS credentials, and
  integrates with the community `ring-sandbox` emulator in tests.

Not yet:

- Rules are opinionated toward homes (quiet hours, aides, packages) and live in one method.
- No OAuth account-linking client, which every Ring Appstore app needs.
- Python only; much Ring Appstore work is TypeScript.
- SQLite, single process, unproven at scale.

## Planned

### 1. OAuth token client — done (2026-09-25)

`stoop.sources.ring_oauth`: one-way (Ring Appstore) and partner-initiated (PKCE) flows,
refresh, nonce matching, `TokenStore` protocol with a SQLite implementation and pluggable
encryption, `RingLinker` glue. With this, `stoop` is a complete Ring integration layer:
link, listen, backfill, decide.

### 2. Rule registry — done (2026-09-25)

`stoop.policy.rules` holds `RuleRegistry` / `SweepRegistry`; `stoop.policy.home_rules` is the
default set as plain named functions. Apps add, move, replace or disable rules and sweep
checks without forking. Behavior of the default set is unchanged (all prior tests pass).

### 3. Drop-in FastAPI router

`stoop.contrib.fastapi` with `/webhooks/ring`, `/auth/ring/start`, `/auth/ring/callback`
and a health check, wired to a `Pipeline`. Porchlight becomes the reference user.

### 4. Publish to PyPI with a 30-minute guide

"Build a Ring app in 30 minutes": link an account, receive a webhook, get a decision, show it.
Pin the emulator as the test double.

### Later

- Typed device and capability models (today the history client returns dicts).
- Multi-tenant conveniences: per-account webhook routing helpers, site provisioning from a
  linked account's device list.
- Long-term memory adapter (Bedrock AgentCore Memory) behind the same `Store` interface.
- A TypeScript port of the event model and webhook verification, so Appstore apps built on
  Ring's Next.js sample can share the schema.

## Positioning

`ring-sandbox` helps you test against Ring. `stoop` helps you decide what to do with what
Ring tells you. They are complementary, and `stoop` uses `ring-sandbox` in its own tests.
