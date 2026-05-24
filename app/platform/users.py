"""Local user, session, API-key, and quota store."""

import asyncio
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from app.platform.config.snapshot import get_config
from app.platform.paths import data_path


SESSION_COOKIE = "grok2api_session"


@dataclass(slots=True)
class AuthContext:
    kind: str
    user: dict[str, Any] | None = None
    api_key: dict[str, Any] | None = None
    global_key: bool = False


def _now() -> int:
    return int(time.time())


def _json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    data["allowed_models"] = _json_load(data.get("allowed_models"), [])
    data["profile"] = _json_load(data.pop("profile_json", None), {})
    return data


class UserStore:
    def __init__(self) -> None:
        self.path = data_path("users.db")
        self._lock = asyncio.Lock()
        self._ready = False

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    async def initialize(self) -> None:
        if self._ready:
            return
        async with self._lock:
            if self._ready:
                return
            await asyncio.to_thread(self._initialize_sync)
            self._ready = True

    def _initialize_sync(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    username TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    avatar_url TEXT NOT NULL DEFAULT '',
                    level INTEGER NOT NULL DEFAULT 0,
                    role TEXT NOT NULL DEFAULT 'user',
                    status TEXT NOT NULL DEFAULT 'active',
                    webchat_enabled INTEGER NOT NULL DEFAULT 1,
                    api_enabled INTEGER NOT NULL DEFAULT 1,
                    quota_limit INTEGER NOT NULL DEFAULT 1000,
                    quota_used INTEGER NOT NULL DEFAULT 0,
                    quota_window_seconds INTEGER NOT NULL DEFAULT 86400,
                    quota_reset_at INTEGER NOT NULL DEFAULT 0,
                    allowed_models TEXT NOT NULL DEFAULT '[]',
                    profile_json TEXT NOT NULL DEFAULT '{}',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    last_login_at INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(provider, subject)
                );
                CREATE TABLE IF NOT EXISTS user_api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_user_api_keys_hash ON user_api_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_user_sessions_hash ON user_sessions(token_hash);
                """
            )

    def _default_quota_limit(self) -> int:
        return int(get_config("users.default_quota_limit", 1000) or 1000)

    def _default_quota_window(self) -> int:
        return int(get_config("users.default_quota_window_seconds", 86400) or 86400)

    async def upsert_oidc_user(self, profile: dict[str, Any]) -> dict[str, Any]:
        await self.initialize()
        provider = str(profile.get("provider") or "linuxdo")
        subject = str(profile.get("sub") or profile.get("id") or "").strip()
        if not subject:
            raise ValueError("OIDC profile is missing subject")
        username = str(
            profile.get("preferred_username")
            or profile.get("username")
            or profile.get("login")
            or profile.get("name")
            or subject
        ).strip()
        display_name = str(profile.get("name") or username).strip()
        email = str(profile.get("email") or "").strip()
        avatar = str(profile.get("picture") or profile.get("avatar_url") or "").strip()
        level = _extract_level(profile)
        user_id = f"{provider}:{subject}"
        now = _now()

        async with self._lock:
            return await asyncio.to_thread(
                self._upsert_oidc_user_sync,
                user_id,
                provider,
                subject,
                username,
                display_name,
                email,
                avatar,
                level,
                profile,
                now,
            )

    def _upsert_oidc_user_sync(
        self,
        user_id: str,
        provider: str,
        subject: str,
        username: str,
        display_name: str,
        email: str,
        avatar: str,
        level: int,
        profile: dict[str, Any],
        now: int,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO users (
                        id, provider, subject, username, display_name, email, avatar_url,
                        level, quota_limit, quota_window_seconds, quota_reset_at,
                        allowed_models, profile_json, created_at, updated_at, last_login_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        provider,
                        subject,
                        username,
                        display_name,
                        email,
                        avatar,
                        level,
                        self._default_quota_limit(),
                        self._default_quota_window(),
                        now + self._default_quota_window(),
                        _json_dump(get_config("users.default_allowed_models", []) or []),
                        _json_dump(profile),
                        now,
                        now,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE users
                    SET username = ?, display_name = ?, email = ?, avatar_url = ?,
                        level = ?, profile_json = ?, updated_at = ?, last_login_at = ?
                    WHERE id = ?
                    """,
                    (
                        username,
                        display_name,
                        email,
                        avatar,
                        level,
                        _json_dump(profile),
                        now,
                        now,
                        user_id,
                    ),
                )
            return _row_to_dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        await self.initialize()
        return await asyncio.to_thread(self._get_user_sync, user_id)

    def _get_user_sync(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            return _row_to_dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())

    async def list_users(self) -> list[dict[str, Any]]:
        await self.initialize()
        return await asyncio.to_thread(self._list_users_sync)

    def _list_users_sync(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
            users = [_row_to_dict(row) for row in rows]
            key_rows = conn.execute(
                "SELECT id, user_id, key_prefix, name, enabled, created_at, last_used_at FROM user_api_keys ORDER BY created_at DESC"
            ).fetchall()
            by_user: dict[str, list[dict[str, Any]]] = {}
            for row in key_rows:
                item = dict(row)
                by_user.setdefault(item["user_id"], []).append(item)
            for user in users:
                user["api_keys"] = by_user.get(user["id"], [])
            return users

    async def patch_user(self, user_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        await self.initialize()
        allowed = {
            "role",
            "status",
            "webchat_enabled",
            "api_enabled",
            "quota_limit",
            "quota_window_seconds",
            "quota_used",
            "quota_reset_at",
            "allowed_models",
            "notes",
        }
        updates = {k: v for k, v in patch.items() if k in allowed}
        if not updates:
            user = await self.get_user(user_id)
            if user is None:
                raise KeyError(user_id)
            return user
        async with self._lock:
            return await asyncio.to_thread(self._patch_user_sync, user_id, updates)

    def _patch_user_sync(self, user_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        encoded: dict[str, Any] = {}
        for key, value in updates.items():
            if key in {"webchat_enabled", "api_enabled"}:
                encoded[key] = 1 if bool(value) else 0
            elif key in {"quota_limit", "quota_window_seconds", "quota_used", "quota_reset_at"}:
                encoded[key] = int(value)
            elif key == "allowed_models":
                encoded[key] = _json_dump(value or [])
            else:
                encoded[key] = "" if value is None else str(value)
        encoded["updated_at"] = _now()
        sets = ", ".join(f"{key} = ?" for key in encoded)
        values = list(encoded.values()) + [user_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE users SET {sets} WHERE id = ?", values)
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise KeyError(user_id)
            return _row_to_dict(row)

    async def delete_user(self, user_id: str) -> bool:
        await self.initialize()
        async with self._lock:
            return await asyncio.to_thread(self._delete_user_sync, user_id)

    def _delete_user_sync(self, user_id: str) -> bool:
        with self._connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM user_api_keys WHERE user_id = ?", (user_id,))
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            return cur.rowcount > 0

    async def reset_quota(self, user_id: str) -> dict[str, Any]:
        await self.initialize()
        async with self._lock:
            return await asyncio.to_thread(self._reset_quota_sync, user_id)

    def _reset_quota_sync(self, user_id: str) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise KeyError(user_id)
            user = _row_to_dict(row)
            window = max(1, int(user["quota_window_seconds"]))
            conn.execute(
                "UPDATE users SET quota_used = 0, quota_reset_at = ?, updated_at = ? WHERE id = ?",
                (now + window, now, user_id),
            )
            return _row_to_dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())

    async def create_api_key(self, user_id: str, name: str = "") -> dict[str, Any]:
        await self.initialize()
        secret = "sk-user-" + secrets.token_urlsafe(32)
        key_id = "key_" + secrets.token_urlsafe(12)
        now = _now()
        async with self._lock:
            await asyncio.to_thread(self._create_api_key_sync, key_id, user_id, secret, name, now)
        return {
            "id": key_id,
            "key": secret,
            "key_prefix": secret[:18],
            "name": name,
            "created_at": now,
            "enabled": True,
        }

    def _create_api_key_sync(self, key_id: str, user_id: str, secret: str, name: str, now: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO user_api_keys (id, user_id, key_hash, key_prefix, name, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (key_id, user_id, _hash_secret(secret), secret[:18], name or "", now),
            )

    async def list_api_keys(self, user_id: str) -> list[dict[str, Any]]:
        await self.initialize()
        return await asyncio.to_thread(self._list_api_keys_sync, user_id)

    def _list_api_keys_sync(self, user_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, user_id, key_prefix, name, enabled, created_at, last_used_at FROM user_api_keys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    async def delete_api_key(self, key_id: str, user_id: str | None = None) -> bool:
        await self.initialize()
        async with self._lock:
            return await asyncio.to_thread(self._delete_api_key_sync, key_id, user_id)

    def _delete_api_key_sync(self, key_id: str, user_id: str | None) -> bool:
        with self._connect() as conn:
            if user_id is None:
                cur = conn.execute("DELETE FROM user_api_keys WHERE id = ?", (key_id,))
            else:
                cur = conn.execute("DELETE FROM user_api_keys WHERE id = ? AND user_id = ?", (key_id, user_id))
            return cur.rowcount > 0

    async def lookup_api_key(self, secret: str) -> AuthContext | None:
        await self.initialize()
        return await asyncio.to_thread(self._lookup_api_key_sync, secret)

    def _lookup_api_key_sync(self, secret: str) -> AuthContext | None:
        with self._connect() as conn:
            key = conn.execute(
                "SELECT * FROM user_api_keys WHERE key_hash = ? AND enabled = 1",
                (_hash_secret(secret),),
            ).fetchone()
            if key is None:
                return None
            user = _row_to_dict(conn.execute("SELECT * FROM users WHERE id = ?", (key["user_id"],)).fetchone())
            if user is None:
                return None
            conn.execute("UPDATE user_api_keys SET last_used_at = ? WHERE id = ?", (_now(), key["id"]))
            return AuthContext(kind="user_api_key", user=user, api_key=dict(key))

    async def create_session(self, user_id: str) -> str:
        await self.initialize()
        token = "sess_" + secrets.token_urlsafe(40)
        session_id = "sess_" + secrets.token_urlsafe(12)
        ttl = int(get_config("users.session_ttl_seconds", 2592000) or 2592000)
        now = _now()
        async with self._lock:
            await asyncio.to_thread(self._create_session_sync, session_id, user_id, token, now, now + ttl)
        return token

    def _create_session_sync(self, session_id: str, user_id: str, token: str, now: int, expires_at: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO user_sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, user_id, _hash_secret(token), now, expires_at, now),
            )

    async def get_session(self, token: str | None) -> AuthContext | None:
        if not token:
            return None
        await self.initialize()
        return await asyncio.to_thread(self._get_session_sync, token)

    def _get_session_sync(self, token: str) -> AuthContext | None:
        now = _now()
        with self._connect() as conn:
            session = conn.execute(
                "SELECT * FROM user_sessions WHERE token_hash = ? AND expires_at > ?",
                (_hash_secret(token), now),
            ).fetchone()
            if session is None:
                return None
            user = _row_to_dict(conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone())
            if user is None:
                return None
            conn.execute("UPDATE user_sessions SET last_seen_at = ? WHERE id = ?", (now, session["id"]))
            return AuthContext(kind="user_session", user=user, api_key=None)

    async def delete_session(self, token: str | None) -> None:
        if not token:
            return
        await self.initialize()
        async with self._lock:
            await asyncio.to_thread(self._delete_session_sync, token)

    def _delete_session_sync(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (_hash_secret(token),))

    async def consume_quota(self, user_id: str, amount: int = 1) -> dict[str, Any]:
        await self.initialize()
        async with self._lock:
            return await asyncio.to_thread(self._consume_quota_sync, user_id, amount)

    def _consume_quota_sync(self, user_id: str, amount: int) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise KeyError(user_id)
            user = _row_to_dict(row)
            limit = int(user["quota_limit"])
            used = int(user["quota_used"])
            window = max(1, int(user["quota_window_seconds"]))
            reset_at = int(user["quota_reset_at"])
            if reset_at <= now:
                used = 0
                reset_at = now + window
            if limit >= 0 and used + amount > limit:
                user["quota_used"] = used
                user["quota_reset_at"] = reset_at
                user["quota_remaining"] = 0
                user["quota_exceeded"] = True
                return user
            used += amount
            conn.execute(
                "UPDATE users SET quota_used = ?, quota_reset_at = ?, updated_at = ? WHERE id = ?",
                (used, reset_at, now, user_id),
            )
            user["quota_used"] = used
            user["quota_reset_at"] = reset_at
            user["quota_remaining"] = None if limit < 0 else max(0, limit - used)
            user["quota_exceeded"] = False
            return user


def _extract_level(profile: dict[str, Any]) -> int:
    for key in ("trust_level", "linuxdo_trust_level", "level", "min_level"):
        try:
            return int(profile.get(key))
        except (TypeError, ValueError):
            continue
    return 0


_store = UserStore()


def get_user_store() -> UserStore:
    return _store


__all__ = ["AuthContext", "SESSION_COOKIE", "UserStore", "get_user_store"]
