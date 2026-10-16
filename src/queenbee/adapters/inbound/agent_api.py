"""Port d'entrée n°2 : messages JSON des agents, authentifiés par HMAC-SHA256.

Ordre des contrôles (du moins cher au plus cher) : taille, signature, schéma, valeurs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Final

from queenbee.domain.model import DomainError, SecurityEvent

MAX_BODY: Final = 4096  # 4 Kio
_FIELDS: Final = frozenset({"source_ip", "username", "action", "timestamp"})


class UnauthenticatedError(Exception):
    """La signature est absente ou fausse : le message n'est pas lu."""


def sign(body: bytes, key: bytes) -> str:
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def parse_agent_message(body: bytes, signature: str, key: bytes) -> SecurityEvent:
    if len(body) > MAX_BODY:
        raise DomainError("message trop gros")
    # compare_digest : temps constant, donc pas de fuite par chronométrage (EX-01).
    # On compare des octets : une signature non ASCII ne doit pas faire planter la comparaison.
    if not isinstance(signature, str) or not hmac.compare_digest(
        sign(body, key).encode(), signature.encode()
    ):
        raise UnauthenticatedError("signature invalide")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:  # JSON cassé, UTF-8 cassé, imbrication abusive
        raise DomainError("JSON invalide") from exc
    # Schéma strict : exactement ces 4 champs, tous des chaînes. Un champ en trop est refusé
    # (sinon un attaquant pourrait tenter de glisser « is_admin » ou autre).
    if (
        not isinstance(data, dict)
        or data.keys() != _FIELDS
        or not all(isinstance(v, str) for v in data.values())
    ):
        raise DomainError("schéma invalide")
    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(data["source_ip"], data["username"], data["action"], timestamp)
