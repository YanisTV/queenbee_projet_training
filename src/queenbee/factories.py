"""Fabrique abstraite : une « famille » cohérente de composants, prod ou mémoire.

Le piège évité : mélanger une vraie base et une fausse notification (ou l'inverse).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Protocol

from queenbee.adapters.outbound.notifiers import LogNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository, Notifier


class ComponentFactory(Protocol):
    def repository(self) -> IncidentRepository: ...

    def notifier(self) -> Notifier: ...


@dataclass(frozen=True, slots=True)
class InMemoryFactory:
    """Famille « tests » : tout en mémoire, rien à nettoyer."""

    def repository(self) -> IncidentRepository:
        return InMemoryIncidentRepository()

    def notifier(self) -> Notifier:
        return MemoryNotifier()


@dataclass(frozen=True, slots=True)
class ProdFactory:
    """Famille « production » : SQLite et notification par journal."""

    db_path: str

    def repository(self) -> IncidentRepository:
        return SqliteIncidentRepository(sqlite3.connect(self.db_path))

    def notifier(self) -> Notifier:
        return LogNotifier()
