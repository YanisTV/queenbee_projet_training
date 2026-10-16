"""Démo du parcours complet : python demo_parcours.py  (avec QUEENBEE_AGENT_KEY défini).

Exemple PowerShell :
    $env:QUEENBEE_AGENT_KEY = "00" * 32
    $env:PYTHONPATH = "src"
    python demo_parcours.py
"""

import json
import os

from queenbee.adapters.inbound.agent_api import UnauthenticatedError, sign
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.services import AccessDeniedError
from queenbee.bootstrap import build_app
from queenbee.config import settings_from_env
from queenbee.domain.model import IncidentStatus, Principal

GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


def main() -> None:
    # Base en mémoire par défaut pour la démo ; QUEENBEE_DB peut la remplacer.
    env = {"QUEENBEE_DB": ":memory:", **os.environ}
    settings = settings_from_env(env)  # refuse de démarrer sans clé valide
    print("Configuration :", settings)  # la clé n'apparaît pas (repr=False)
    app = build_app(settings)

    print("\n1) Ingestion : 5 échecs de connexion + 1 ligne piégée")
    incidents = app.ingest_lines([GOOD] * 5 + ["Failed password for root'; DROP TABLE x;--"])
    print(f"   incidents ouverts : {len(incidents)} | lignes rejetées : {app.rejected}")

    print("\n2) Message d'agent signé, puis falsifié")
    body = json.dumps(
        {
            "source_ip": "10.0.0.7",
            "username": "root",
            "action": "login_failed",
            "timestamp": "2026-10-14T09:00:00+00:00",
        }
    ).encode()
    app.ingest_agent_message(body, sign(body, settings.hmac_key))
    print("   message signé : accepté")
    try:
        app.ingest_agent_message(body, "0" * 64)
    except UnauthenticatedError:
        print("   fausse signature : refusée")

    print("\n3) Contrôle d'accès")
    analyst = Principal("alice", frozenset({"analyst"}))
    viewer = Principal("bob", frozenset({"viewer"}))
    incident_id = incidents[0].id
    try:
        app.move_incident(viewer, incident_id, IncidentStatus.TRIAGED)
    except AccessDeniedError:
        print("   viewer ne peut pas modifier un incident : refusé")
    app.move_incident(analyst, incident_id, IncidentStatus.TRIAGED)
    print(f"   analyste : incident passé à {app.open_incidents(analyst)[0].status}")

    print("\n4) Réponse active annulable")
    firewall, history = InMemoryFirewall(), CommandHistory()
    history.run(BlockIpCommand(firewall, "10.0.0.66"))
    print(f"   IP bloquées : {sorted(firewall.blocked)}")
    history.undo_last()
    print(f"   après annulation : {sorted(firewall.blocked)}")


if __name__ == "__main__":
    main()
