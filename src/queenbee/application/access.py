"""Contrôle d'accès : les rôles se vérifient ICI, dans la couche application (EX-05)."""

from __future__ import annotations

from uuid import UUID

from queenbee.application.ports import IncidentRepository
from queenbee.domain.model import Incident, Principal

READ_ROLES = frozenset({"viewer", "analyst", "admin"})
WRITE_ROLES = frozenset({"analyst", "admin"})


class AccessDeniedError(Exception):
    """L'appelant n'a pas le rôle requis."""


def require_role(principal: Principal, allowed: frozenset[str]) -> None:
    if principal.roles.isdisjoint(allowed):
        # Message générique : on ne dit pas quel rôle manquait (pas d'aide à l'attaquant).
        raise AccessDeniedError("accès refusé")


class IncidentReadProxy:
    """Proxy de protection : MÊME interface que IncidentRepository, rôle vérifié avant de déléguer.

    Le client n'a pas à changer : il reçoit le proxy à la place du dépôt. Lire demande un rôle
    de lecture, écrire (`save`) demande un rôle d'écriture.
    """

    def __init__(self, repository: IncidentRepository, principal: Principal) -> None:
        self._repository = repository
        self._principal = principal

    def save(self, incident: Incident) -> None:
        require_role(self._principal, WRITE_ROLES)
        self._repository.save(incident)

    def get(self, incident_id: UUID) -> Incident | None:
        require_role(self._principal, READ_ROLES)
        return self._repository.get(incident_id)

    def list_open(self) -> list[Incident]:
        require_role(self._principal, READ_ROLES)
        return self._repository.list_open()
