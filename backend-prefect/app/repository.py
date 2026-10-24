"""Persistencia de usuarios y códigos de respaldo.

Dos implementaciones intercambiables de la misma interfaz:
- SQLiteUserRepository: por defecto, archivo local (laboratorio controlado).
- SupabaseUserRepository: tablas en Supabase/Postgres (ver supabase_schema.sql).
"""

import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from functools import lru_cache

from . import config
from .state_machine import TwoFactorStatus


class UsernameTaken(Exception):
    pass


class UserRepository(ABC):
    @abstractmethod
    def create_user(self, username: str, password_hash: str) -> dict: ...

    @abstractmethod
    def get_user(self, user_id: int) -> dict | None: ...

    @abstractmethod
    def get_user_by_username(self, username: str) -> dict | None: ...

    @abstractmethod
    def update_two_factor(self, user_id: int, status: TwoFactorStatus, secret: str | None) -> None: ...

    @abstractmethod
    def replace_backup_codes(self, user_id: int, code_hashes: list[str]) -> None: ...

    @abstractmethod
    def consume_backup_code(self, user_id: int, code_hash: str) -> bool:
        """Marca el código como usado de forma atómica. True si estaba disponible."""

    @abstractmethod
    def count_unused_backup_codes(self, user_id: int) -> int: ...


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SQLiteUserRepository(UserRepository):
    def __init__(self, path: str):
        self.path = path
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    twofa_status TEXT NOT NULL DEFAULT 'DISABLED',
                    totp_secret TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    code_hash TEXT NOT NULL,
                    used_at TEXT
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_user(self, username, password_hash):
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, password_hash, _now_iso()),
                )
                user_id = cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise UsernameTaken(username) from exc
        return self.get_user(user_id)

    def get_user(self, user_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def get_user_by_username(self, username):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def update_two_factor(self, user_id, status, secret):
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET twofa_status = ?, totp_secret = ? WHERE id = ?",
                (TwoFactorStatus(status).value, secret, user_id),
            )

    def replace_backup_codes(self, user_id, code_hashes):
        with self._connect() as conn:
            conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
            conn.executemany(
                "INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
                [(user_id, h) for h in code_hashes],
            )

    def consume_backup_code(self, user_id, code_hash):
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE backup_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                (_now_iso(), user_id, code_hash),
            )
            return cur.rowcount == 1

    def count_unused_backup_codes(self, user_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used_at IS NULL", (user_id,)
            ).fetchone()
        return row[0]


class SupabaseUserRepository(UserRepository):
    def __init__(self, url: str, key: str):
        from supabase import create_client

        if not url or not key:
            raise RuntimeError("DB_BACKEND=supabase requiere SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY")
        self.client = create_client(url, key)

    def create_user(self, username, password_hash):
        if self.get_user_by_username(username):
            raise UsernameTaken(username)
        res = (
            self.client.table("users")
            .insert({"username": username, "password_hash": password_hash})
            .execute()
        )
        return res.data[0]

    def get_user(self, user_id):
        res = self.client.table("users").select("*").eq("id", user_id).limit(1).execute()
        return res.data[0] if res.data else None

    def get_user_by_username(self, username):
        res = self.client.table("users").select("*").eq("username", username).limit(1).execute()
        return res.data[0] if res.data else None

    def update_two_factor(self, user_id, status, secret):
        self.client.table("users").update(
            {"twofa_status": TwoFactorStatus(status).value, "totp_secret": secret}
        ).eq("id", user_id).execute()

    def replace_backup_codes(self, user_id, code_hashes):
        self.client.table("backup_codes").delete().eq("user_id", user_id).execute()
        self.client.table("backup_codes").insert(
            [{"user_id": user_id, "code_hash": h} for h in code_hashes]
        ).execute()

    def consume_backup_code(self, user_id, code_hash):
        # UPDATE condicionado a used_at IS NULL: solo una petición concurrente gana.
        res = (
            self.client.table("backup_codes")
            .update({"used_at": _now_iso()})
            .eq("user_id", user_id)
            .eq("code_hash", code_hash)
            .is_("used_at", "null")
            .execute()
        )
        return len(res.data) == 1

    def count_unused_backup_codes(self, user_id):
        res = (
            self.client.table("backup_codes")
            .select("id")
            .eq("user_id", user_id)
            .is_("used_at", "null")
            .execute()
        )
        return len(res.data)


@lru_cache(maxsize=1)
def get_repository() -> UserRepository:
    if config.DB_BACKEND == "supabase":
        return SupabaseUserRepository(config.SUPABASE_URL, config.SUPABASE_KEY)
    return SQLiteUserRepository(config.SQLITE_PATH)
