"""Composition root + Facade : le SEUL endroit qui assemble les adaptateurs.

Le reste du code reçoit ses dépendances par le constructeur (inversion de dépendances).
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from queenbee.adapters.inbound.agent_api import UnauthenticatedError, parse_agent_message
from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.adapters.outbound.notifiers import AuditedNotifier, RateLimitedNotifier
from queenbee.application.access import IncidentReadProxy
from queenbee.application.ports import IncidentRepository
from queenbee.application.services import DetectionService, IncidentService
from queenbee.config import Settings
from queenbee.domain.model import (
    DomainError,
    Incident,
    IncidentStatus,
    Principal,
    SecurityEvent,
)
from queenbee.domain.rules import BruteForceRule, PortScanRule, RuleSet
from queenbee.factories import ComponentFactory, ProdFactory


class QueenBee:
    """Façade : une API simple devant le parseur, la détection et les incidents."""

    def __init__(
        self, settings: Settings, detection: DetectionService, repository: IncidentRepository
    ) -> None:
        self._settings = settings
        self._detection = detection
        self._repository = repository
        self.rejected = 0

    def ingest_lines(self, lines: Iterable[str]) -> list[Incident]:
        """Lignes de journal -> événements valides -> détection (rejets comptés)."""
        events: list[SecurityEvent] = []
        for line in lines:
            try:
                events.append(parse_sshd_line(line))
            except DomainError:
                self.rejected += 1
        return self._detection.ingest(events)

    def ingest_agent_message(self, body: bytes, signature: str) -> list[Incident]:
        """Message signé d'un agent. UnauthenticatedError remonte à l'appelant (réponse 401)."""
        try:
            event = parse_agent_message(body, signature, self._settings.hmac_key)
        except (DomainError, UnauthenticatedError):
            self.rejected += 1
            raise
        return self._detection.ingest([event])

    def open_incidents(self, principal: Principal) -> list[Incident]:
        return IncidentReadProxy(self._repository, principal).list_open()

    def move_incident(
        self, principal: Principal, incident_id: UUID, new_status: IncidentStatus
    ) -> Incident:
        return IncidentService(self._repository).move(principal, incident_id, new_status)


def build_app(settings: Settings, factory: ComponentFactory | None = None) -> QueenBee:
    """Assemble l'application. Sans `factory`, on prend la famille « production »."""
    factory = factory or ProdFactory(settings.db_path)
    repository = factory.repository()
    # Décorateurs empilés : audit -> limite de débit -> notifieur réel.
    notifier = AuditedNotifier(RateLimitedNotifier(factory.notifier(), 100, 60.0))
    rule = RuleSet((BruteForceRule(settings.bf_threshold), PortScanRule()))
    return QueenBee(settings, DetectionService(rule, repository, [notifier]), repository)
