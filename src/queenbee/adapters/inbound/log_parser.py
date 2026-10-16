"""Port d'entrée n°1 : lignes de journal sshd. Entrée NON FIABLE, donc validée strictement."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

from queenbee.domain.model import LOGIN_FAILED, LOGIN_OK, DomainError, SecurityEvent

# Longueur bornée AVANT toute analyse : une ligne géante est refusée sans être lue (EX-02).
MAX_LINE: Final = 300

# Aucun quantificateur imbriqué, aucun `.*` : le temps d'analyse reste linéaire.
_LINE_RE: Final = re.compile(
    r"(?P<ts>[0-9T:+\-.Z]{19,35}) sshd: (?P<verb>Failed|Accepted) password for "
    r"(?P<user>[A-Za-z0-9_.-]{1,32}) from (?P<ip>[0-9A-Fa-f:.]{2,45})"
)
_ACTIONS: Final = {"Failed": LOGIN_FAILED, "Accepted": LOGIN_OK}


def parse_sshd_line(line: str) -> SecurityEvent:
    """Transforme une ligne en SecurityEvent, ou lève DomainError. Jamais autre chose."""
    if len(line) > MAX_LINE:
        raise DomainError("ligne trop longue")
    match = _LINE_RE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        raise DomainError("ligne non reconnue")
    try:
        timestamp = datetime.fromisoformat(match["ts"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    # SecurityEvent revalide tout (IP réelle, fuseau, allowlist) : défense en profondeur.
    return SecurityEvent(match["ip"], match["user"], _ACTIONS[match["verb"]], timestamp)
