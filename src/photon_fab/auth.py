"""为 HTTP 和命令行入口提供的角色权限层。"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


ROLES = {"operator", "engineer", "quality", "admin"}
PERMISSIONS = {
    "operator": {"read", "measure"},
    "engineer": {"read", "measure", "analyze", "submit"},
    "quality": {"read", "measure", "analyze", "approve", "release"},
    "admin": {"read", "measure", "analyze", "submit", "approve", "release", "admin"},
}

SESSION_TTL = timedelta(hours=8)


@dataclass(frozen=True)
class User:
    user_id: str
    role: str
    active: bool


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 80_000).hex()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    """解析过期时间，统一返回带时区的 UTC datetime。

    新数据一律为带偏移量的 ISO-8601；历史裸时间（无时区）按 UTC 处理，
    而不是依赖进程本地时区，从而避免 UTC/夏令时环境下的误判。
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class Auth:
    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock | None = None):
        self.db = connection
        # 与 PhotonService 共用同一把可重入锁，使 HTTP 工作线程的数据库访问串行化。
        self.lock = lock if lock is not None else threading.RLock()
        self.db.execute("""CREATE TABLE IF NOT EXISTS users(
            user_id TEXT PRIMARY KEY, role TEXT NOT NULL, salt TEXT NOT NULL,
            password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1)""")
        self.db.commit()

    def create_user(self, user_id: str, password: str, role: str = "operator") -> User:
        with self.lock:
            if role not in ROLES or len(password) < 8:
                raise ValueError("invalid role or password")
            salt = secrets.token_hex(16)
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,1,?)", (user_id, role, salt, _hash(password, salt), _utcnow().isoformat()))
            self.db.commit()
            return User(user_id, role, True)

    def login(self, user_id: str, password: str) -> str:
        with self.lock:
            row = self.db.execute("SELECT role,salt,password_hash,active FROM users WHERE user_id=?", (user_id,)).fetchone()
            if not row or not row[3] or not hmac.compare_digest(_hash(password, row[1]), row[2]):
                raise PermissionError("invalid credentials")
            token = secrets.token_urlsafe(24)
            # 过期时间以带时区的 UTC ISO-8601 落库，重启后仍按库内的绝对时刻判定。
            expires_at = (_utcnow() + SESSION_TTL).isoformat()
            self.db.execute("INSERT INTO sessions VALUES(?,?,?,1)", (token, user_id, expires_at))
            self.db.commit()
            return token

    def current(self, token: str) -> User:
        with self.lock:
            row = self.db.execute("""SELECT u.user_id,u.role,u.active,s.active,s.expires_at
                FROM sessions s JOIN users u ON u.user_id=s.user_id
                WHERE s.token=?""", (token,)).fetchone()
            if not row:
                raise PermissionError("session expired")
            # 用户停用或会话失效必须立即反映（每次都查库，不做进程内缓存）。
            if not row[2] or not row[3]:
                raise PermissionError("session expired")
            if _parse_utc(row[4]) <= _utcnow():
                raise PermissionError("session expired")
            return User(row[0], row[1], True)

    def require(self, token: str, permission: str) -> User:
        with self.lock:
            user = self.current(token)
            if permission not in PERMISSIONS[user.role]:
                raise PermissionError("permission denied")
            return user

    def deactivate(self, user_id: str) -> None:
        with self.lock:
            self.db.execute("UPDATE users SET active=0 WHERE user_id=?", (user_id,))
            self.db.execute("UPDATE sessions SET active=0 WHERE user_id=?", (user_id,))
            self.db.commit()
