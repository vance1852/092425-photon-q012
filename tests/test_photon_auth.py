from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from photon_fab.auth import Auth
from photon_fab.service import PhotonService


class MutableClock:
    """可在测试中推进的时间源，始终返回带时区的 UTC 时间。"""

    def __init__(self, current: datetime):
        if current.tzinfo is None:
            raise ValueError("时钟必须带时区")
        self.current = current.astimezone(timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs) -> None:
        self.current += timedelta(**kwargs)


class SessionTimeTests(unittest.TestCase):
    def setUp(self) -> None:
        # 选在北美夏令时切换当天，证明跨 DST 判定只看 UTC 瞬间。
        self.clock = MutableClock(datetime(2026, 11, 1, 5, 0, tzinfo=timezone.utc))
        self.service = PhotonService(clock=self.clock)
        self.service.auth.create_user("admin", "secret-password", "admin")

    def test_new_session_is_not_immediately_expired(self) -> None:
        token = self.service.auth.login("admin", "secret-password")
        # 创建后立即使用必须有效（曾经在 UTC 环境下被误判过期）。
        self.service.auth.current(token)
        raw = self.service.db.execute("SELECT expires_at FROM sessions").fetchone()[0]
        # 落库为带偏移量的 UTC ISO-8601 文本。
        self.assertTrue(raw.endswith("+00:00"), raw)
        stored = datetime.fromisoformat(raw)
        self.assertEqual(stored.utcoffset(), timedelta(0))
        self.assertEqual(stored - self.clock(), timedelta(hours=8))

    def test_session_valid_across_daylight_saving_boundary(self) -> None:
        token = self.service.auth.login("admin", "secret-password")
        # 推进 7 小时，跨过 America/New_York 的夏令时切换（EDT->EST），
        # 墙钟偏移发生变化但 UTC 未到 8 小时，会话仍应有效。
        self.clock.advance(hours=7)
        self.service.auth.current(token)

    def test_session_expires_after_ttl(self) -> None:
        token = self.service.auth.login("admin", "secret-password")
        self.clock.advance(hours=8)
        with self.assertRaises(PermissionError):
            self.service.auth.current(token)

    def test_session_valid_just_before_ttl(self) -> None:
        token = self.service.auth.login("admin", "secret-password")
        self.clock.advance(hours=7, minutes=59, seconds=59)
        self.service.auth.current(token)

    def test_bad_password_is_rejected(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.auth.login("admin", "wrong-password")


class DeactivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc))
        self.service = PhotonService(clock=self.clock)
        self.service.auth.create_user("admin", "secret-password", "admin")
        self.service.auth.create_user("op", "operator-password", "engineer")
        self.token = self.service.auth.login("op", "operator-password")

    def test_deactivation_revokes_existing_token_immediately(self) -> None:
        # 停用前 token 可以建批次、读批次。
        self.service.create_lot(self.token, "LOT-1", "sensor", "P1", 3)
        self.assertEqual(self.service.get_lot(self.token, "LOT-1")["lot_id"], "LOT-1")
        admin_token = self.service.auth.login("admin", "secret-password")
        self.service.deactivate_user(admin_token, "op")
        # 停用后旧 token 立即不能再读取批次。
        with self.assertRaises(PermissionError):
            self.service.auth.current(self.token)
        with self.assertRaises(PermissionError):
            self.service.get_lot(self.token, "LOT-1")

    def test_deactivated_user_cannot_login(self) -> None:
        admin_token = self.service.auth.login("admin", "secret-password")
        self.service.deactivate_user(admin_token, "op")
        with self.assertRaises(PermissionError):
            self.service.auth.login("op", "operator-password")

    def test_non_admin_cannot_deactivate(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.deactivate_user(self.token, "admin")

    def test_deactivate_unknown_user(self) -> None:
        admin_token = self.service.auth.login("admin", "secret-password")
        with self.assertRaises(KeyError):
            self.service.auth.deactivate("ghost")
        # 未知用户不应影响其它会话。
        self.service.auth.current(self.token)


class RestartPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "photon.sqlite3")
        self.clock = MutableClock(datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _open(self) -> PhotonService:
        return PhotonService(self.db_path, clock=self.clock)

    def test_expiry_honoured_after_restart(self) -> None:
        first = self._open()
        first.auth.create_user("admin", "secret-password", "admin")
        token = first.auth.login("admin", "secret-password")
        first.db.close()

        # 模拟服务重启：新进程打开同一个数据库文件。
        restarted = self._open()
        restarted.auth.current(token)  # 未过期，仍可用

        # 经过 TTL 后，重启后的进程按数据库里的 expires_at 判定为过期。
        self.clock.advance(hours=8, seconds=1)
        with self.assertRaises(PermissionError):
            restarted.auth.current(token)
        restarted.db.close()

    def test_restart_reads_stored_expiry_verbatim(self) -> None:
        first = self._open()
        first.auth.create_user("admin", "secret-password", "admin")
        token = first.auth.login("admin", "secret-password")
        # 直接把过期时间改成遥远的未来，证明重启后完全以库内值为准。
        future = (self.clock() + timedelta(days=30)).isoformat()
        first.db.execute("UPDATE sessions SET expires_at=? WHERE token=?", (future, token))
        first.db.commit()
        first.db.close()

        self.clock.advance(hours=20)  # 已超过默认 8 小时 TTL
        restarted = self._open()
        restarted.auth.current(token)  # 因库内 expires_at 在未来，仍然有效
        restarted.db.close()

    def test_naive_legacy_expiry_treated_as_utc(self) -> None:
        # 历史上由 SQLite datetime('now') 写入的 naive 文本按 UTC 解释。
        service = self._open()
        service.auth.create_user("admin", "secret-password", "admin")
        token = service.auth.login("admin", "secret-password")
        service.db.execute(
            "UPDATE sessions SET expires_at=? WHERE token=?",
            ("2026-09-24 13:00:00", token),
        )
        service.db.commit()
        # 当前 12:00 UTC，naive 的 13:00 被视为 13:00 UTC，尚未过期。
        service.auth.current(token)
        self.clock.advance(hours=1, seconds=1)
        with self.assertRaises(PermissionError):
            service.auth.current(token)


if __name__ == "__main__":
    unittest.main()
