"""为 HTTP 和命令行入口提供的角色权限层。

所有时间统一使用“带时区的 UTC”：会话过期时间以 aware UTC 的 ISO-8601
字符串写入 SQLite，校验时只比较 UTC 瞬间（instant），因此与容器时区、
夏令时切换无关，服务重启后仍按数据库中保存的过期时间判定。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable


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


def utc_now() -> datetime:
    """始终返回带时区的当前 UTC 时间。"""
    return datetime.now(timezone.utc)


def to_utc_text(value: datetime) -> str:
    """把 aware 时间序列化为带偏移量的 UTC ISO-8601 文本。"""
    if value.tzinfo is None:
        raise ValueError("时间必须带时区")
    return value.astimezone(timezone.utc).isoformat()


def parse_utc(value: str) -> datetime:
    """把库内时间解析为带时区的 UTC 时间。

    新数据一律带偏移量；历史上由 SQLite ``datetime('now')`` 写入的
    naive 文本按 UTC 处理，避免重启后旧会话被误判。
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class Auth:
    def __init__(self, connection: sqlite3.Connection, clock: Callable[[], datetime] | None = None):
        self.db = connection
        # 可注入的时间源，默认走系统 UTC；测试时可替换为冻结时钟。
        self._clock = clock or utc_now
        self.db.execute("""CREATE TABLE IF NOT EXISTS users(
            user_id TEXT PRIMARY KEY, role TEXT NOT NULL, salt TEXT NOT NULL,
            password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1)""")
        self.db.commit()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("时钟必须返回带时区的时间")
        return now.astimezone(timezone.utc)

    def create_user(self, user_id: str, password: str, role: str = "operator") -> User:
        if role not in ROLES or len(password) < 8:
            raise ValueError("invalid role or password")
        salt = secrets.token_hex(16)
        self.db.execute(
            "INSERT INTO users VALUES(?,?,?,?,1,?)",
            (user_id, role, salt, _hash(password, salt), to_utc_text(self._now())),
        )
        self.db.commit()
        return User(user_id, role, True)

    def login(self, user_id: str, password: str) -> str:
        row = self.db.execute("SELECT role,salt,password_hash,active FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row or not row[3] or not hmac.compare_digest(_hash(password, row[1]), row[2]):
            raise PermissionError("invalid credentials")
        token = secrets.token_urlsafe(24)
        # 过期时间在 Python 侧按 UTC 瞬间计算并带时区落库，
        # 不依赖 SQLite 的 datetime('now')，也不受容器时区影响。
        expires_at = to_utc_text(self._now() + SESSION_TTL)
        self.db.execute("INSERT INTO sessions VALUES(?,?,?,1)", (token, user_id, expires_at))
        self.db.commit()
        return token

    def current(self, token: str) -> User:
        row = self.db.execute("""SELECT u.user_id,u.role,u.active,s.active,s.expires_at
            FROM sessions s JOIN users u ON u.user_id=s.user_id
            WHERE s.token=?""", (token,)).fetchone()
        # 每次都重新读取 users/sessions：账号停用会即时传播到所有已签发 token，
        # 不存在进程内缓存导致的“旧 token 偶尔仍可读”。
        if not row or not row[2] or not row[3]:
            raise PermissionError("session expired")
        if parse_utc(row[4]) <= self._now():
            raise PermissionError("session expired")
        return User(row[0], row[1], True)

    def require(self, token: str, permission: str) -> User:
        user = self.current(token)
        if permission not in PERMISSIONS[user.role]:
            raise PermissionError("permission denied")
        return user

    def deactivate(self, user_id: str) -> None:
        if not self.db.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone():
            raise KeyError(user_id)
        with self.db:
            self.db.execute("UPDATE users SET active=0 WHERE user_id=?", (user_id,))
            self.db.execute("UPDATE sessions SET active=0 WHERE user_id=?", (user_id,))
