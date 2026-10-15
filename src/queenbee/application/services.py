"""Cas d'usage. Tout ce dont ils ont besoin leur est transmis par le constructeur."""

from __future__ import annotations

from collections.abc import Sequence

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import Rule


class DetectionService:
    """Évalue des événements, ouvre un incident par alerte, prévient les notifieurs."""

    def __init__(
        self, rule: Rule, repository: IncidentRepository, notifiers: Sequence[Notifier]
    ) -> None:
        self._rule = rule
        self._repository = repository
        self._notifiers = tuple(notifiers)

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._repository.save(incident)
            for notifier in self._notifiers:
                notifier.notify(alert)
            incidents.append(incident)
        return incidents
