"""Cachés en memoria (dict) del laboratorio.

Al ser memoria del proceso, el backend debe correr con un solo worker de uvicorn.
"""

import threading
import time

from . import config


class AntiReplayCache:
    """Recuerda (user_id, código) usados durante `ttl` segundos."""

    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self._used: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for key in [k for k, expires in self._used.items() if expires <= now]:
            del self._used[key]

    def was_used(self, user_id, code: str) -> bool:
        now = time.time()
        with self._lock:
            self._purge(now)
            return (str(user_id), code) in self._used

    def mark_used(self, user_id, code: str) -> bool:
        """Registra el código. Devuelve False si otro request ya lo había registrado."""
        now = time.time()
        with self._lock:
            self._purge(now)
            key = (str(user_id), code)
            if key in self._used:
                return False
            self._used[key] = now + self.ttl
            return True

    def clear(self) -> None:
        with self._lock:
            self._used.clear()


class PreAuthSessionStore:
    """Estado de cada pre_auth_token (por jti): intentos fallidos y si ya se consumió."""

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def register(self, jti: str, expires_at: int) -> None:
        with self._lock:
            now = time.time()
            for key in [k for k, s in self._sessions.items() if s["exp"] <= now]:
                del self._sessions[key]
            self._sessions[jti] = {"exp": expires_at, "attempts": 0, "consumed": False}

    def get(self, jti: str) -> dict | None:
        with self._lock:
            session = self._sessions.get(jti)
            return dict(session) if session else None

    def record_failure(self, jti: str) -> int:
        with self._lock:
            session = self._sessions.get(jti)
            if not session:
                return 0
            session["attempts"] += 1
            return session["attempts"]

    def consume(self, jti: str) -> bool:
        with self._lock:
            session = self._sessions.get(jti)
            if not session or session["consumed"]:
                return False
            session["consumed"] = True
            return True

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


anti_replay_cache = AntiReplayCache(config.ANTI_REPLAY_TTL_SECONDS)
pre_auth_sessions = PreAuthSessionStore()
