# Friction log

Running notes on developer friction met while building on Ring, Alexa+, and AWS during the
Build, Ship, Shape hackathon (Aug 31 – Oct 23, 2026). Each entry: what I tried, what got in
the way, what I did instead, and what would have helped.

## 2026-09-25 — Ring: "simulator" in the hackathon brief does not exist as such

- **Tried:** find the Ring simulator the hackathon page mentions ("APIs, SDKs, simulators, or devices").
- **Friction:** Ring's docs have a Playground (30-minute token, one sandbox Doorbell Pro) but no
  event simulator. Other entrants report the Playground device logs only live-view sessions:
  no motion or doorbell events in history, no stored snapshots. Webhooks require a registered
  app, which asks for business details and a physical device.
- **Did instead:** built a labeled synthetic event source in `stoop` and use the community
  `ring-sandbox` emulator for webhook and history integration tests.
- **Would help:** an official "inject event" button in the Playground, and a note in the
  hackathon brief pointing at what the Playground can and cannot produce.

## 2026-09-25 — Ring: history events carry no `sub_type` in the documented shape

- **Friction:** the documented `history-events` resource has `event_type` (motion/ding/on_demand)
  and start/end, while webhooks carry `sub_type` (human/vehicle/package). Backfilling from
  history therefore loses the classification that the policy engine needs most.
- **Did instead:** map history motion to `detected=unknown` and rely on webhooks for live
  classification.

## 2026-09-25 — Alexa+: 500 ms round-trip budget shapes the whole architecture

- **Friction:** the MCP Toolkit quickstart requires tool responses under 500 ms. Any LLM call
  inside a tool blows the budget.
- **Did instead:** all reasoning runs on the ingestion path; MCP tools only read precomputed
  state from SQLite.
- **Would help:** an explicit "long-running tool" pattern (progress notifications or async
  result polling) in the Alexa+ toolkit docs.

## 2026-09-25 — Alexa+: dev environment doc lists macOS or Ubuntu only

- **Friction:** Windows is not listed for the Alexa AI CLI environment.
- **Did instead:** plan to run the CLI in WSL2 Ubuntu.

## 2026-09-25 — Ring: the Token Exchange URL request is not documented

- **Tried:** implement the one-way account-linking flow from the API documentation.
- **Friction:** the docs say Ring "sends the authorization code directly to your Token
  Exchange URL (backend-to-backend)" but never show the request: method, headers, content
  type or field names. The Account Link redirect is documented (`nonce`, `time` in ms), the
  token exchange and nonce math are documented, the inbound call is not.
- **Did instead:** the library takes a bare `code` string; the app's route accepts both JSON
  and form bodies and logs the first real request shape from staging.
- **Would help:** one example request in the docs, and a "send test code" button in the
  developer console.
