"""Règles de détection : Strategy (une règle = une stratégie), Composite (RuleSet), Factory."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from queenbee.domain.model import (
    LOGIN_FAILED,
    PORT_PROBE,
    Alert,
    DomainError,
    SecurityEvent,
    Severity,
)

MAX_RULE_THRESHOLD = 10_000


class Rule(Protocol):
    """Contrat commun : tout objet qui sait évaluer des événements est une règle."""

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]: ...


def _check_threshold(threshold: object) -> int:
    # bool est un sous-type de int : True passerait pour 1 sans ce contrôle.
    if type(threshold) is not int or not 1 <= threshold <= MAX_RULE_THRESHOLD:
        raise DomainError("seuil invalide")
    return threshold


@dataclass(frozen=True, slots=True)
class BruteForceRule:
    """Au moins `threshold` échecs de connexion depuis la même IP."""

    threshold: int = 5

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        counts = Counter(e.source_ip for e in events if e.action == LOGIN_FAILED)
        return [
            Alert("brute_force", ip, Severity.HIGH, f"{n} échecs de connexion")
            for ip, n in counts.items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class PortScanRule:
    """Au moins `threshold` sondages de port depuis la même IP."""

    threshold: int = 10

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        counts = Counter(e.source_ip for e in events if e.action == PORT_PROBE)
        return [
            Alert("port_scan", ip, Severity.MEDIUM, f"{n} sondages de port")
            for ip, n in counts.items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : un groupe de règles se comporte comme une seule règle."""

    rules: tuple[Rule, ...]

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        return [alert for rule in self.rules for alert in rule.evaluate(events)]


# Registre fermé : nom -> constructeur. Jamais de getattr/importlib sur une chaîne externe.
_REGISTRY: Mapping[str, Callable[[int], Rule]] = MappingProxyType(
    {"brute_force": BruteForceRule, "port_scan": PortScanRule}
)


def build_rule(config: Mapping[str, object]) -> Rule:
    """Factory : construit une règle à partir d'une configuration non fiable."""
    kind = config.get("kind")
    # isinstance d'abord : une liste en guise de nom ferait planter la recherche dans le dict.
    if not isinstance(kind, str) or kind not in _REGISTRY:
        raise DomainError("type de règle inconnu")
    return _REGISTRY[kind](_check_threshold(config.get("threshold")))
