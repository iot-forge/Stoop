# Changelog

All notable changes to `stoop` are listed here. The project follows [Semantic Versioning](https://semver.org/).
Before 1.0 the API may change between minor versions, and every such change is noted.

## Unreleased

## 0.1.0

First public release.

- Events: one normalized shape for doorbell presses, motion with person, vehicle, animal and
  package detection, door sensors, device health, environmental sensors and account lifecycle
  events.
- Sources: Ring Partner API webhooks (signature verified over the raw body) and history, Ring
  account linking (one-way and partner-initiated OAuth with PKCE, encrypted token store), and
  labeled synthetic scenarios for demos and tests.
- Memory: SQLite store for sites, people, expected visits (one-off or recurring), visits,
  decisions and key/value state.
- Routines: weekly rates per weekday and hour, an anomaly score, and daily-presence detection.
- Policy: a rule registry with graded home rules (visitors, departures, no-shows, inactivity,
  quiet hours, doors left open, sensor maintenance, comfort and alerts), a sweep for things that
  did not happen, and suppression so one visitor is one alert.
- Reasoning: an offline reasoner that adds context, and an Amazon Bedrock reasoner (Nova 2 Lite
  by default) that rewrites alert text for the reader, with a timeout, an offline fallback, a
  one-step cap on severity changes, and a day summary for digests.
