"""Modèle du domaine : objets qui ne peuvent pas être invalides.

Aucune dépendance technique ici (ni base, ni réseau, ni framework) : seulement la
bibliothèque standard. Toute donnée externe est contrôlée à la construction.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final
from uuid import UUID, uuid4

LOGIN_FAILED: Final = "login_failed"
LOGIN_OK: Final = "login_ok"
PORT_PROBE: Final = "port_probe"

# Liste blanche (allowlist) : tout ce qui n'y figure pas est refusé.
ALLOWED_ACTIONS: Final = frozenset({LOGIN_FAILED, LOGIN_OK, PORT_PROBE})

# Pas de quantificateur imbriqué : aucun risque de ReDoS. fullmatch = pas de reste toléré.
_USERNAME_RE: Final = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_RULE_RE: Final = re.compile(r"[a-z_]{1,32}")
_MAX_DETAIL: Final = 200


class DomainError(Exception):
    """Une règle métier ou une validation est violée.

    Les messages sont volontairement génériques : on n'y recopie jamais la donnée reçue
    (elle vient peut-être d'un attaquant, risque de falsification des journaux).
    """


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class IncidentStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    CLOSED = "closed"


def _check_ip(value: object) -> None:
    # ip_address(123) accepterait un entier : on exige donc explicitement une chaîne.
    if not isinstance(value, str):
        raise DomainError("IP invalide")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DomainError("IP invalide") from exc


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Événement remonté par un agent. Figé : impossible de le modifier après coup."""

    source_ip: str
    username: str
    action: str
    timestamp: datetime

    def __post_init__(self) -> None:
        _check_ip(self.source_ip)
        if not isinstance(self.username, str) or not _USERNAME_RE.fullmatch(self.username):
            raise DomainError("nom d'utilisateur invalide")
        if self.action not in ALLOWED_ACTIONS:
            raise DomainError("action inconnue")
        if not isinstance(self.timestamp, datetime) or self.timestamp.utcoffset() is None:
            raise DomainError("horodatage sans fuseau")


@dataclass(frozen=True, slots=True)
class Alert:
    """Résultat d'une règle de détection."""

    rule: str
    source_ip: str
    severity: Severity
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not _RULE_RE.fullmatch(self.rule):
            raise DomainError("nom de règle invalide")
        _check_ip(self.source_ip)
        try:
            Severity(self.severity)
        except ValueError as exc:
            raise DomainError("gravité invalide") from exc
        # isprintable() refuse les retours à la ligne : pas de fausse ligne dans les journaux.
        if (
            not isinstance(self.detail, str)
            or len(self.detail) > _MAX_DETAIL
            or not self.detail.isprintable()
        ):
            raise DomainError("détail invalide")


# Machine à états : seules ces transitions existent (on ne saute pas le triage).
_TRANSITIONS: Final = MappingProxyType(
    {
        IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED}),
        IncidentStatus.TRIAGED: frozenset({IncidentStatus.CLOSED}),
        IncidentStatus.CLOSED: frozenset[IncidentStatus](),
    }
)


@dataclass(slots=True)
class Incident:
    """Dossier ouvert à partir d'une alerte. Seul son statut évolue, et sous contrôle."""

    alert: Alert
    id: UUID = field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN

    def transition_to(self, new_status: IncidentStatus) -> None:
        if new_status not in _TRANSITIONS[self.status]:
            raise DomainError("transition interdite")
        self.status = new_status
