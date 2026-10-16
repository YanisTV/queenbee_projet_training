"""Réponse active : pattern Command (chaque action sait s'exécuter ET s'annuler)."""

from __future__ import annotations

import ipaddress
from typing import Protocol

from queenbee.application.ports import Firewall
from queenbee.domain.model import DomainError


class InMemoryFirewall:
    """Faux pare-feu pour les tests et la démo."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def block(self, ip: str) -> None:
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        self.blocked.discard(ip)


class Command(Protocol):
    def execute(self) -> None: ...

    def undo(self) -> None: ...


class BlockIpCommand:
    """Bloque une IP. L'IP est validée à la construction : rien de forgé n'atteint le pare-feu."""

    def __init__(self, firewall: Firewall, ip: str) -> None:
        # ip_address lève ValueError sur une chaîne comme « 10.0.0.1; iptables -F » (EX-04).
        self._ip = str(ipaddress.ip_address(ip))
        self._firewall = firewall

    def execute(self) -> None:
        self._firewall.block(self._ip)

    def undo(self) -> None:
        self._firewall.unblock(self._ip)


class CommandHistory:
    """Garde les commandes exécutées pour pouvoir annuler la dernière."""

    def __init__(self) -> None:
        self._done: list[Command] = []

    def run(self, command: Command) -> None:
        command.execute()
        self._done.append(command)

    def undo_last(self) -> None:
        if not self._done:
            raise DomainError("rien à annuler")
        self._done.pop().undo()
