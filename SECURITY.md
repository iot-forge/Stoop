# Security

stoop handles webhook signatures, OAuth tokens and event data about people's homes. If you find
a vulnerability, please email the maintainer listed in `pyproject.toml` instead of opening a
public issue. Expect an acknowledgement within a few days.

Notes for integrators:

- Verify Ring webhooks with `parse_ring_webhook(..., signing_key=...)` over the raw request body.
  Never re-serialize the JSON before verifying.
- Store Ring tokens with a cipher (`SqliteTokenStore(store, cipher=Fernet(...))`). The default
  `NoCipher` is for tests only.
- The Bedrock reasoner sends event context and, optionally, a camera snapshot to your own AWS
  account. Nothing leaves that account.
