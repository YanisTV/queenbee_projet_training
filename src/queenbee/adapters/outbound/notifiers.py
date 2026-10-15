"""Notifieurs sortants : un adaptateur de test (mémoire) et un adaptateur « prod » (journal)."""

from __future__ import annotations

import logging

from queenbee.domain.model import Alert

_log = logging.getLogger("queenbee.alerts")


class MemoryNotifier:
    """Garde les alertes en mémoire : sert aux tests et aux démonstrations."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class LogNotifier:
    """Écrit l'alerte dans le journal. Les champs sont déjà validés par Alert."""

    def notify(self, alert: Alert) -> None:
        _log.warning(
            "ALERTE %s ip=%s gravité=%s : %s",
            alert.rule,
            alert.source_ip,
            alert.severity.name,
            alert.detail,
        )
