from __future__ import annotations

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo

import pytest

from stoop import ExpectedVisit, Person, PolicyConfig, PolicyEngine, Role, Site, Store
from stoop.sources.synthetic import generate_baseline

TZ = "America/New_York"
SITE_ID = "home-1"


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


@pytest.fixture
def site(store: Store) -> Site:
    return store.put_site(Site(id=SITE_ID, name="Mom's house", timezone=TZ))


@pytest.fixture
def people(store: Store, site: Site) -> dict[str, Person]:
    maria = store.put_person(Person(site_id=site.id, name="Maria", role=Role.AIDE, phone="+15550100"))
    dana = store.put_person(Person(site_id=site.id, name="Dana", role=Role.FAMILY, phone="+15550101"))
    return {"maria": maria, "dana": dana}


@pytest.fixture
def aide_schedule(store: Store, site: Site, people: dict[str, Person]) -> ExpectedVisit:
    return store.put_expected(
        ExpectedVisit(
            site_id=site.id,
            label="Morning aide",
            person_id=people["maria"].id,
            days_of_week=[0, 2, 4],
            local_start=time(9, 0),
            local_end=time(10, 30),
            expected_duration_min=90,
        )
    )


@pytest.fixture
def engine(store: Store, site: Site) -> PolicyEngine:
    return PolicyEngine(store, config=PolicyConfig())


def local(y: int, mo: int, d: int, h: int, mi: int = 0) -> datetime:
    """Local time in the test timezone as an aware datetime."""
    return datetime(y, mo, d, h, mi, tzinfo=ZoneInfo(TZ))


# Monday 2026-09-21 is a convenient anchor: aide days are Mon/Wed/Fri.
MONDAY = local(2026, 9, 21, 12)


@pytest.fixture
def warm_engine(engine: PolicyEngine, site: Site) -> PolicyEngine:
    """Engine with four weeks of synthetic routine history loaded (no decisions)."""
    history = generate_baseline(site_id=site.id, days=28, end=MONDAY.astimezone(UTC), tz=TZ)
    for ev in history:
        engine.handle(ev, learn_only=True)
    return engine
