"""Ports : les contrats que la couche application exige du monde extérieur.

Ce sont des Protocol : un adaptateur n'a pas besoin d'hériter, il lui suffit d'avoir les
bonnes méthodes. Le sens des dépendances reste : adapters -> application -> domain.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from queenbee.domain.model import Alert, Incident


class IncidentRepository(Protocol):
    def save(self, incident: Incident) -> None: ...

    def get(self, incident_id: UUID) -> Incident | None: ...

    def list_open(self) -> list[Incident]: ...


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...
