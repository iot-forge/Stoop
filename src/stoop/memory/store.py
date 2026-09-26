"""SQLite-backed store. Standard library only, one file per deployment, safe to vendor.

All rows keep the pydantic JSON as the source of truth plus a few indexed columns for
queries. Timestamps are stored as ISO-8601 UTC strings so lexical order == time order.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from stoop.events import Event, EventKind
from stoop.memory.models import Decision, ExpectedVisit, Person, Site, Visit, VisitStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL, kind TEXT NOT NULL, device_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL, dedupe_key TEXT, json TEXT NOT NULL,
  UNIQUE(site_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS ix_events_site_time ON events(site_id, occurred_at);
CREATE TABLE IF NOT EXISTS persons (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS expected_visits (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS visits (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL, started_at TEXT NOT NULL, status TEXT NOT NULL, json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_visits_site_time ON visits(site_id, started_at);
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL, event_id TEXT, created_at TEXT NOT NULL,
  action TEXT NOT NULL, severity TEXT NOT NULL, acknowledged_at TEXT, json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_decisions_site_time ON decisions(site_id, created_at);
CREATE TABLE IF NOT EXISTS kv (site_id TEXT NOT NULL, key TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(site_id, key));
"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


class Store:
    """Thread-safe SQLite store. Use ``":memory:"`` for tests."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _rows(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    # ------------------------------------------------------------------ sites
    def put_site(self, site: Site) -> Site:
        self._exec("INSERT OR REPLACE INTO sites(id, json) VALUES (?, ?)", (site.id, site.model_dump_json()))
        return site

    def get_site(self, site_id: str) -> Site | None:
        rows = self._rows("SELECT json FROM sites WHERE id=?", (site_id,))
        return Site.model_validate_json(rows[0]["json"]) if rows else None

    def list_sites(self) -> list[Site]:
        return [Site.model_validate_json(r["json"]) for r in self._rows("SELECT json FROM sites ORDER BY id")]

    # ----------------------------------------------------------------- events
    def put_event(self, event: Event) -> bool:
        """Insert; returns False when the event (by id or dedupe key) already exists."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO events(id, site_id, kind, device_id, occurred_at, dedupe_key, json)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    event.id,
                    event.site_id,
                    event.kind.value,
                    event.device_id,
                    _iso(event.occurred_at),
                    event.dedupe_key,
                    event.model_dump_json(),
                ),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def get_event(self, event_id: str) -> Event | None:
        rows = self._rows("SELECT json FROM events WHERE id=?", (event_id,))
        return Event.model_validate_json(rows[0]["json"]) if rows else None

    def events(
        self,
        site_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        kinds: Iterable[EventKind] | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> list[Event]:
        sql = "SELECT json FROM events WHERE site_id=?"
        params: list[Any] = [site_id]
        if since is not None:
            sql += " AND occurred_at>=?"
            params.append(_iso(since))
        if until is not None:
            sql += " AND occurred_at<=?"
            params.append(_iso(until))
        if kinds:
            ks = [k.value for k in kinds]
            sql += f" AND kind IN ({','.join('?' * len(ks))})"
            params.extend(ks)
        sql += " ORDER BY occurred_at " + ("DESC" if newest_first else "ASC")
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [Event.model_validate_json(r["json"]) for r in self._rows(sql, params)]

    def last_event(self, site_id: str) -> Event | None:
        evs = self.events(site_id, limit=1, newest_first=True)
        return evs[0] if evs else None

    # ---------------------------------------------------------------- persons
    def put_person(self, person: Person) -> Person:
        self._exec(
            "INSERT OR REPLACE INTO persons(id, site_id, json) VALUES (?,?,?)",
            (person.id, person.site_id, person.model_dump_json()),
        )
        return person

    def get_person(self, person_id: str) -> Person | None:
        rows = self._rows("SELECT json FROM persons WHERE id=?", (person_id,))
        return Person.model_validate_json(rows[0]["json"]) if rows else None

    def persons(self, site_id: str) -> list[Person]:
        return [Person.model_validate_json(r["json"]) for r in self._rows("SELECT json FROM persons WHERE site_id=? ORDER BY id", (site_id,))]

    # ------------------------------------------------------- expected visits
    def put_expected(self, ev: ExpectedVisit) -> ExpectedVisit:
        self._exec(
            "INSERT OR REPLACE INTO expected_visits(id, site_id, json) VALUES (?,?,?)",
            (ev.id, ev.site_id, ev.model_dump_json()),
        )
        return ev

    def delete_expected(self, expected_id: str) -> None:
        self._exec("DELETE FROM expected_visits WHERE id=?", (expected_id,))

    def expected(self, site_id: str) -> list[ExpectedVisit]:
        return [
            ExpectedVisit.model_validate_json(r["json"])
            for r in self._rows("SELECT json FROM expected_visits WHERE site_id=? ORDER BY id", (site_id,))
        ]

    # ----------------------------------------------------------------- visits
    def put_visit(self, visit: Visit) -> Visit:
        self._exec(
            "INSERT OR REPLACE INTO visits(id, site_id, started_at, status, json) VALUES (?,?,?,?,?)",
            (visit.id, visit.site_id, _iso(visit.started_at), visit.status.value, visit.model_dump_json()),
        )
        return visit

    def get_visit(self, visit_id: str) -> Visit | None:
        rows = self._rows("SELECT json FROM visits WHERE id=?", (visit_id,))
        return Visit.model_validate_json(rows[0]["json"]) if rows else None

    def open_visit(self, site_id: str) -> Visit | None:
        rows = self._rows(
            "SELECT json FROM visits WHERE site_id=? AND status=? ORDER BY started_at DESC LIMIT 1",
            (site_id, VisitStatus.OPEN.value),
        )
        return Visit.model_validate_json(rows[0]["json"]) if rows else None

    def visits(self, site_id: str, *, since: datetime | None = None, limit: int = 100) -> list[Visit]:
        sql = "SELECT json FROM visits WHERE site_id=?"
        params: list[Any] = [site_id]
        if since is not None:
            sql += " AND started_at>=?"
            params.append(_iso(since))
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        return [Visit.model_validate_json(r["json"]) for r in self._rows(sql, params)]

    # -------------------------------------------------------------- decisions
    def put_decision(self, d: Decision) -> Decision:
        self._exec(
            "INSERT OR REPLACE INTO decisions(id, site_id, event_id, created_at, action, severity, acknowledged_at, json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                d.id,
                d.site_id,
                d.event_id,
                _iso(d.created_at),
                d.action.value,
                d.severity.value,
                _iso(d.acknowledged_at) if d.acknowledged_at else None,
                d.model_dump_json(),
            ),
        )
        return d

    def get_decision(self, decision_id: str) -> Decision | None:
        rows = self._rows("SELECT json FROM decisions WHERE id=?", (decision_id,))
        return Decision.model_validate_json(rows[0]["json"]) if rows else None

    def decisions(
        self,
        site_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        unacknowledged_only: bool = False,
        limit: int = 100,
    ) -> list[Decision]:
        sql = "SELECT json FROM decisions WHERE site_id=?"
        params: list[Any] = [site_id]
        if since is not None:
            sql += " AND created_at>=?"
            params.append(_iso(since))
        if until is not None:
            sql += " AND created_at<=?"
            params.append(_iso(until))
        if unacknowledged_only:
            sql += " AND acknowledged_at IS NULL AND action IN ('notify','escalate')"
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [Decision.model_validate_json(r["json"]) for r in self._rows(sql, params)]

    def acknowledge(self, decision_id: str, by: str, at: datetime | None = None) -> Decision | None:
        d = self.get_decision(decision_id)
        if d is None:
            return None
        d.acknowledged_at = at or datetime.now(tz=UTC)
        d.acknowledged_by = by
        return self.put_decision(d)

    def decision_for_rule(
        self, site_id: str, rule: str, *, since: datetime, until: datetime | None = None, key: str | None = None
    ) -> Decision | None:
        """Most recent decision with ``rule`` (and optional metadata ``key``) in [since, until]. Used to avoid repeats.

        Pass ``until`` (normally the event time) so replayed or backdated events never see
        decisions from their own future.
        """
        for d in self.decisions(site_id, since=since, until=until, limit=200):
            if d.rule == rule and (key is None or d.metadata.get("key") == key):
                return d
        return None

    # --------------------------------------------------------------------- kv
    def set_state(self, site_id: str, key: str, value: Any) -> None:
        self._exec("INSERT OR REPLACE INTO kv(site_id, key, json) VALUES (?,?,?)", (site_id, key, json.dumps(value)))

    def get_state(self, site_id: str, key: str, default: Any = None) -> Any:
        rows = self._rows("SELECT json FROM kv WHERE site_id=? AND key=?", (site_id, key))
        return json.loads(rows[0]["json"]) if rows else default

    def states_with_prefix(self, site_id: str, prefix: str) -> dict[str, Any]:
        rows = self._rows("SELECT key, json FROM kv WHERE site_id=? AND key LIKE ?", (site_id, prefix + "%"))
        return {r["key"]: json.loads(r["json"]) for r in rows}
