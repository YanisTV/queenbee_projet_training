"""Jour 2 — compléments : cas limites de sécurité non couverts par les tests fournis."""

import json
from uuid import uuid4

import pytest

from queenbee.adapters.inbound.agent_api import (
    MAX_BODY,
    UnauthenticatedError,
    parse_agent_message,
    sign,
)
from queenbee.adapters.inbound.log_parser import MAX_LINE, parse_sshd_line
from queenbee.adapters.inbound.threat_feed import ThreatFeedTranslator
from queenbee.adapters.outbound.notifiers import MemoryNotifier, RateLimitedNotifier
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.access import AccessDeniedError, IncidentReadProxy
from queenbee.application.ports import IncidentRepository
from queenbee.application.services import DetectionService
from queenbee.bootstrap import build_app
from queenbee.config import ConfigError, SettingsBuilder, settings_from_env
from queenbee.domain.model import (
    Alert,
    DomainError,
    Incident,
    IncidentStatus,
    Principal,
    Severity,
    ThreatIndicator,
)
from queenbee.domain.rules import BruteForceRule
from queenbee.factories import InMemoryFactory

KEY = bytes(range(32))
GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"
ANALYST = Principal("alice", frozenset({"analyst"}))
VIEWER = Principal("bob", frozenset({"viewer"}))
GUEST = Principal("guest", frozenset())


def _signed(body: bytes) -> tuple[bytes, str]:
    return body, sign(body, KEY)


def test_abuse_oversized_body_rejected_before_anything_else() -> None:
    body = b"x" * (MAX_BODY + 1)
    with pytest.raises(DomainError):  # refusé sur la taille, sans même vérifier la signature
        parse_agent_message(body, "peu importe", KEY)


def test_abuse_non_ascii_signature_is_unauthenticated_not_a_crash() -> None:
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(b"{}", "é" * 64, KEY)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"\xff\xfe",  # UTF-8 invalide
        b"[" * 3000 + b"]" * 3000,  # imbrication abusive (RecursionError)
        b"[1, 2]",  # pas un objet
        b'{"source_ip": "10.0.0.1"}',  # champs manquants
        json.dumps(
            {"source_ip": 1, "username": "root", "action": "login_ok", "timestamp": "x"}
        ).encode(),  # valeur non textuelle
        json.dumps(
            {
                "source_ip": "10.0.0.1",
                "username": "root",
                "action": "login_ok",
                "timestamp": "pas-une-date",
            }
        ).encode(),
    ],
)
def test_abuse_signed_but_malformed_message_rejected(body: bytes) -> None:
    with pytest.raises(DomainError):
        parse_agent_message(*_signed(body), KEY)


def test_line_too_long_and_bad_timestamp_rejected() -> None:
    with pytest.raises(DomainError):
        parse_sshd_line("a" * (MAX_LINE + 1))
    with pytest.raises(DomainError):
        parse_sshd_line(GOOD.replace("2026-10-14T09:00:00+02:00", "9999-99-99T99:99:99+02:00"))


def test_accepted_login_is_parsed_and_trailing_newline_tolerated() -> None:
    line = GOOD.replace("Failed", "Accepted") + "\n"
    assert parse_sshd_line(line).action == "login_ok"


def test_threat_feed_unknown_level_and_score_bounds() -> None:
    with pytest.raises(DomainError):
        ThreatFeedTranslator().translate({"indicator": "1.1.1.1", "risk_level": "apocalypse"})
    with pytest.raises(DomainError):
        ThreatIndicator("1.1.1.1", 101)


def test_principal_validation() -> None:
    with pytest.raises(DomainError):
        Principal("alice; DROP", frozenset())
    with pytest.raises(DomainError):
        Principal("alice", {"analyst"})  # type: ignore[arg-type]


def test_proxy_lets_a_viewer_read_but_unknown_id_is_none() -> None:
    app = build_app(settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex()}), InMemoryFactory())
    app.ingest_lines([GOOD] * 5)
    assert len(app.open_incidents(VIEWER)) == 1
    repo = InMemoryFactory().repository()
    assert IncidentReadProxy(repo, VIEWER).get(uuid4()) is None


def test_facade_signed_message_and_incident_lifecycle() -> None:
    app = build_app(settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex()}), InMemoryFactory())
    body = json.dumps(
        {
            "source_ip": "10.0.0.9",
            "username": "root",
            "action": "login_failed",
            "timestamp": "2026-10-14T09:00:00+00:00",
        }
    ).encode()
    assert app.ingest_agent_message(body, sign(body, KEY)) == []  # 1 échec : sous le seuil
    with pytest.raises(UnauthenticatedError):
        app.ingest_agent_message(body, "0" * 64)
    assert app.rejected == 1
    [incident] = app.ingest_lines([GOOD] * 5)
    app.move_incident(ANALYST, incident.id, IncidentStatus.TRIAGED)
    assert app.open_incidents(ANALYST)[0].status is IncidentStatus.TRIAGED


@pytest.mark.parametrize(
    "env",
    [
        {"QUEENBEE_AGENT_KEY": "zz"},  # pas de l'hexadécimal
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "beaucoup"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "0"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "10001"},
    ],
)
def test_bad_environment_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        settings_from_env(env)


def test_builder_rejects_empty_db_path() -> None:
    with pytest.raises(ConfigError):
        SettingsBuilder().hmac_key(KEY).db_path("").build()


def test_rate_limiter_rejects_absurd_parameters_and_empty_history() -> None:
    with pytest.raises(DomainError):
        RateLimitedNotifier(InMemoryFactory().notifier(), 0, 60)
    with pytest.raises(DomainError):
        CommandHistory().undo_last()


def _incident() -> Incident:
    return Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, "x"))


def test_abuse_guest_cannot_read_incidents() -> None:
    proxy = IncidentReadProxy(InMemoryFactory().repository(), GUEST)
    with pytest.raises(AccessDeniedError):
        proxy.list_open()
    with pytest.raises(AccessDeniedError):
        proxy.get(uuid4())


def test_abuse_viewer_cannot_write_through_the_proxy() -> None:
    repo = InMemoryFactory().repository()
    inc = _incident()
    with pytest.raises(AccessDeniedError):
        IncidentReadProxy(repo, VIEWER).save(inc)
    assert repo.get(inc.id) is None  # aucun effet : rien n'a été écrit


def test_proxy_has_the_same_interface_as_the_repository() -> None:
    repo = InMemoryFactory().repository()
    inc = _incident()
    client: IncidentRepository = IncidentReadProxy(repo, ANALYST)  # le client ne change pas
    client.save(inc)
    assert client.get(inc.id) == inc
    assert client.list_open() == [inc]


def test_abuse_forged_ip_never_reaches_the_firewall() -> None:
    firewall = InMemoryFirewall()
    with pytest.raises(ValueError, match="does not appear"):
        BlockIpCommand(firewall, "10.0.0.1; iptables -F")
    assert firewall.blocked == set()


def test_observer_every_subscriber_gets_the_alert_without_touching_the_service() -> None:
    first, second = MemoryNotifier(), MemoryNotifier()
    events = [parse_sshd_line(GOOD)] * 5
    DetectionService(BruteForceRule(), InMemoryFactory().repository(), [first, second]).ingest(
        events
    )
    assert len(first.received) == len(second.received) == 1


def test_move_returns_the_updated_incident_and_principal_helpers() -> None:
    app = build_app(settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex()}), InMemoryFactory())
    [incident] = app.ingest_lines([GOOD] * 5)
    moved = app.move_incident(ANALYST, incident.id, IncidentStatus.TRIAGED)
    assert moved.status is IncidentStatus.TRIAGED
    assert ANALYST.has("analyst") and not ANALYST.has("admin") and ANALYST.user == "alice"


def test_observer_failing_subscriber_does_not_block_others(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BrokenNotifier:
        def notify(self, alert: Alert) -> None:
            raise RuntimeError("simulated subscriber outage")

    healthy = MemoryNotifier()
    service = DetectionService(
        BruteForceRule(), InMemoryFactory().repository(), [BrokenNotifier(), healthy]
    )
    caplog.set_level("ERROR", logger="queenbee.notifications")
    events = [parse_sshd_line(GOOD)] * 5

    [incident] = service.ingest(events)

    assert incident.status is IncidentStatus.OPEN
    assert len(healthy.received) == 1
    assert service.notification_failures == 1
    assert "échec de notification" in caplog.text


@pytest.mark.parametrize("threshold", [0, -1, True, 10_001])
def test_rule_threshold_has_explicit_bounds(threshold: object) -> None:
    with pytest.raises(DomainError):
        BruteForceRule(threshold)  # type: ignore[arg-type]


def test_rule_threshold_accepts_upper_bound() -> None:
    assert BruteForceRule(10_000).threshold == 10_000
