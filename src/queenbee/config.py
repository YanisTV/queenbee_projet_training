"""Configuration : pattern Builder -> Settings figé. Les secrets viennent de l'environnement."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Self

MIN_KEY_BYTES: Final = 32
MAX_BF_THRESHOLD: Final = 10_000
_DEFAULT_DB: Final = "queenbee.db"
_DEFAULT_THRESHOLD: Final = 5


class ConfigError(Exception):
    """Configuration absente ou invalide : l'application refuse de démarrer.

    Les messages ne contiennent jamais la valeur du secret.
    """


@dataclass(frozen=True, slots=True)
class Settings:
    # repr=False : la clé n'apparaît ni dans print(), ni dans les logs, ni dans un traceback.
    hmac_key: bytes = field(repr=False)
    db_path: str = _DEFAULT_DB
    bf_threshold: int = _DEFAULT_THRESHOLD


class SettingsBuilder:
    """On assemble pas à pas ; build() contrôle TOUT et rend un objet figé."""

    def __init__(self) -> None:
        self._hmac_key: bytes | None = None
        self._db_path = _DEFAULT_DB
        self._bf_threshold = _DEFAULT_THRESHOLD

    def hmac_key(self, key: bytes) -> Self:
        self._hmac_key = key
        return self

    def db_path(self, path: str) -> Self:
        self._db_path = path
        return self

    def bf_threshold(self, threshold: int) -> Self:
        self._bf_threshold = threshold
        return self

    def build(self) -> Settings:
        if not isinstance(self._hmac_key, bytes) or len(self._hmac_key) < MIN_KEY_BYTES:
            raise ConfigError(f"clé HMAC absente ou trop courte (minimum {MIN_KEY_BYTES} octets)")
        if not isinstance(self._db_path, str) or not self._db_path:
            raise ConfigError("chemin de base invalide")
        if type(self._bf_threshold) is not int or not 1 <= self._bf_threshold <= MAX_BF_THRESHOLD:
            raise ConfigError("seuil de force brute invalide")
        return Settings(self._hmac_key, self._db_path, self._bf_threshold)


def settings_from_env(env: Mapping[str, str]) -> Settings:
    """Lit la configuration depuis un dictionnaire (os.environ en production)."""
    raw_key = env.get("QUEENBEE_AGENT_KEY")
    if not raw_key:
        raise ConfigError("QUEENBEE_AGENT_KEY manquante")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError as exc:
        raise ConfigError("QUEENBEE_AGENT_KEY doit être en hexadécimal") from exc
    try:
        threshold = int(env.get("QUEENBEE_BF_THRESHOLD", str(_DEFAULT_THRESHOLD)))
    except ValueError as exc:
        raise ConfigError("QUEENBEE_BF_THRESHOLD doit être un entier") from exc
    return (
        SettingsBuilder()
        .hmac_key(key)
        .db_path(env.get("QUEENBEE_DB", _DEFAULT_DB))
        .bf_threshold(threshold)
        .build()
    )
