"""Dépôts d'incidents : en mémoire (tests) et SQLite (prod)."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident (
    id TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity INTEGER NOT NULL,
    detail TEXT NOT NULL,
    status TEXT NOT NULL
)
"""


class InMemoryIncidentRepository:
    def __init__(self) -> None:
        self._items: dict[UUID, Incident] = {}

    def save(self, incident: Incident) -> None:
        self._items[incident.id] = incident

    def get(self, incident_id: UUID) -> Incident | None:
        return self._items.get(incident_id)

    def list_open(self) -> list[Incident]:
        return [i for i in self._items.values() if i.status is not IncidentStatus.CLOSED]


class SqliteIncidentRepository:
    """Toutes les requêtes sont paramétrées (?) : les valeurs ne sont jamais du SQL."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self._conn.execute(_SCHEMA)

    def save(self, incident: Incident) -> None:
        a = incident.alert
        self._conn.execute(
            "INSERT OR REPLACE INTO incident (id, rule, source_ip, severity, detail, status)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (str(incident.id), a.rule, a.source_ip, int(a.severity), a.detail, incident.status),
        )
        self._conn.commit()

    def get(self, incident_id: UUID) -> Incident | None:
        row = self._conn.execute(
            "SELECT id, rule, source_ip, severity, detail, status FROM incident WHERE id = ?",
            (str(incident_id),),
        ).fetchone()
        return None if row is None else _to_incident(row)

    def list_open(self) -> list[Incident]:
        rows = self._conn.execute(
            "SELECT id, rule, source_ip, severity, detail, status FROM incident"
            " WHERE status != ? ORDER BY rowid",
            (IncidentStatus.CLOSED,),
        ).fetchall()
        return [_to_incident(r) for r in rows]


def _to_incident(row: tuple[str, str, str, int, str, str]) -> Incident:
    id_, rule, ip, severity, detail, status = row
    # Reconstitution depuis la base : Alert se revalide, rien n'est cru sur parole.
    return Incident(Alert(rule, ip, Severity(severity), detail), UUID(id_), IncidentStatus(status))
