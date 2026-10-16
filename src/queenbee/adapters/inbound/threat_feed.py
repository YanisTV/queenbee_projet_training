"""Couche anticorruption (ACL) : traduit le vocabulaire d'un flux EXTERNE vers le nôtre.

Le flux dit {"indicator", "risk_level"} ; chez nous c'est un ThreatIndicator(ip, score).
Le modèle du fournisseur ne pénètre jamais le domaine.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from queenbee.domain.model import DomainError, ThreatIndicator

_SCORES: Final = MappingProxyType({"low": 20, "medium": 50, "high": 80, "critical": 100})


class ThreatFeedTranslator:
    def translate(self, raw: Mapping[str, object]) -> ThreatIndicator:
        indicator, level = raw.get("indicator"), raw.get("risk_level")
        if not isinstance(indicator, str) or not isinstance(level, str):
            raise DomainError("indicateur incomplet")
        if level not in _SCORES:
            raise DomainError("niveau de risque inconnu")
        # Seules les IP sont acceptées (pas de nom de domaine) : ThreatIndicator le vérifie.
        return ThreatIndicator(indicator, _SCORES[level])
