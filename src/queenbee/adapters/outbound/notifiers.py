"""Notifieurs sortants : un adaptateur de test (mémoire) et un adaptateur « prod » (journal)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from queenbee.application.ports import Notifier
from queenbee.domain.model import Alert, DomainError

_log = logging.getLogger("queenbee.alerts")
_audit = logging.getLogger("queenbee.audit")


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


class AuditedNotifier:
    """Décorateur : laisse une trace d'audit, puis délègue au notifieur enveloppé (EX-08)."""

    def __init__(self, inner: Notifier) -> None:
        self._inner = inner

    def notify(self, alert: Alert) -> None:
        # Le journal ajoute l'horodatage ; les champs de l'alerte sont déjà validés.
        _audit.info(
            "alerte notifiée rule=%s ip=%s gravité=%s",
            alert.rule,
            alert.source_ip,
            alert.severity.name,
        )
        self._inner.notify(alert)


class RateLimitedNotifier:
    """Décorateur : au plus `max_per_window` alertes par fenêtre de `window_s` secondes (EX-06).

    L'horloge est injectée (`clock`) : les tests la pilotent sans attendre.
    """

    def __init__(
        self,
        inner: Notifier,
        max_per_window: int,
        window_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_window < 1 or window_s <= 0:
            raise DomainError("limite de débit invalide")
        self._inner = inner
        self._max = max_per_window
        self._window_s = window_s
        self._clock = clock
        self._window_start = clock()
        self._count = 0
        self.dropped = 0

    def notify(self, alert: Alert) -> None:
        now = self._clock()
        if now - self._window_start >= self._window_s:
            self._window_start = now
            self._count = 0
        if self._count >= self._max:
            self.dropped += 1
            return
        self._count += 1
        self._inner.notify(alert)
