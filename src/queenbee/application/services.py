"""Cas d'usage. Tout ce dont ils ont besoin leur est transmis par le constructeur."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from uuid import UUID

from queenbee.application.access import WRITE_ROLES, AccessDeniedError, require_role
from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import (
    DomainError,
    Incident,
    IncidentStatus,
    Principal,
    SecurityEvent,
)
from queenbee.domain.rules import Rule

__all__ = ["AccessDeniedError", "DetectionService", "IncidentService"]

_log = logging.getLogger("queenbee.notifications")


class DetectionService:
    """Évalue des événements, ouvre un incident par alerte, prévient les notifieurs."""

    def __init__(
        self, rule: Rule, repository: IncidentRepository, notifiers: Sequence[Notifier]
    ) -> None:
        self._rule = rule
        self._repository = repository
        self._notifiers = tuple(notifiers)
        # Les échecs d'un abonné sont isolés et comptés : les autres restent servis.
        self.notification_failures = 0

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._repository.save(incident)
            for notifier in self._notifiers:
                try:
                    notifier.notify(alert)
                except Exception:
                    # Une panne de notification ne doit ni effacer l'incident ni bloquer
                    # la diffusion aux autres abonnés. L'échec reste observable en audit.
                    self.notification_failures += 1
                    _log.exception("échec de notification rule=%s", alert.rule)
            incidents.append(incident)
        return incidents


class IncidentService:
    """Fait avancer un incident. Ordre : autoriser, vérifier, règle métier, persister."""

    def __init__(self, repository: IncidentRepository) -> None:
        self._repository = repository

    def move(self, principal: Principal, incident_id: UUID, new_status: IncidentStatus) -> Incident:
        require_role(principal, WRITE_ROLES)
        incident = self._repository.get(incident_id)
        if incident is None:
            raise DomainError("incident inconnu")
        incident.transition_to(new_status)
        self._repository.save(incident)
        return incident
