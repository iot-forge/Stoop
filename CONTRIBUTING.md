# Contributing to stoop

Thanks for looking. Bug reports, questions and pull requests are welcome.

## Setup

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check src tests && uv run ruff format src tests
```

Tests run offline. Ring is emulated in-process with `ring-sandbox`, and the Bedrock reasoner is
tested with a fake client, so no account of any kind is needed.

## Ground rules

- Rules always produce a complete decision on their own. A reasoner may reword it and move the
  severity by one step. It can never remove a confirmation requirement or create an alert.
- Every event goes through the same pipeline regardless of source. New sources normalize into
  `stoop.events.Event`; they do not add rules.
- No identification of people by face. Detections are limited to person, vehicle, animal and
  package.
- Keep the core dependency list small (httpx, pydantic). Optional integrations go behind extras.
- Add a test for every behavior change, and a line to `CHANGELOG.md` under "Unreleased".

## Releasing (maintainers)

1. Update the version in `pyproject.toml` and `src/stoop/__init__.py`, and move the "Unreleased"
   notes in `CHANGELOG.md` under the new version.
2. Tag and publish a GitHub release named `vX.Y.Z`. The publish workflow builds the package and
   uploads it to PyPI through trusted publishing.
