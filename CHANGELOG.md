# Changelog

All notable changes to `stoop` are listed here. The project follows [Semantic Versioning](https://semver.org/).
Before 1.0 the API may change between minor versions, and every such change is noted.

## Unreleased

## 0.1.2

- Ring: `RingHistory.start_live()` and `stop_live()` open and close a live view over WebRTC
  (Ring's WHEP endpoint). The browser's SDP offer goes in, the SDP answer comes back as a
  `LiveSession`; both the JSON:API and plain-SDP response shapes are handled.

## 0.1.1

- Ring: `RingHistory.device_status()` reads a device's current readings (online, battery,
  temperature, humidity, contact state) from the status endpoint, so sensors can be polled
  without thresholds set in the Ring app.
- Ring: `status_events()` turns polled readings into events on change: `SENSOR_ALERT` when a
  reading crosses a `ComfortThresholds` limit, `SENSOR_CLEARED` when it returns, and
  `DOOR_OPENED`/`DOOR_CLOSED` when a contact sensor's state flips, and tamper alerts. Contact
  sensors report `contact_detection.faulted` rather than a state string; both are read. Stable
  dedupe keys per reading.
- Rules: comfort alerts say the actual reading ("Kitchen is 88°F. That is warm for this home."),
  in Fahrenheit for homes in US time zones or when the site's `units` metadata is "F".

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
