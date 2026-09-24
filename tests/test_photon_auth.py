from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from photon_fab.auth import _parse_utc
from photon_fab.service import PhotonService


class SessionTimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PhotonService()
        self.service.bootstrap_admin("admin", "admin-pass-1")
        self.service.auth.create_user("eng", "eng-pass-123", "engineer")

    def test_new_session_is_not_immediately_expired(self) -> None:
        token = self.service.auth.login("eng", "eng-pass-123")
        user = self.service.auth.current(token)
        self.assertEqual(user.user_id, "eng")

    def test_expiry_stored_as_tz_aware_utc_iso(self) -> None:
        token = self.service.auth.login("eng", "eng-pass-123")
        raw = self.service.db.execute(
            "SELECT expires_at FROM sessions WHERE token=?", (token,)
        ).fetchone()[0]
        parsed = datetime.fromisoformat(raw)
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset(), timedelta(0))
        # 有效期约为 8 小时。
        self.assertGreater(parsed - datetime.now(timezone.utc), timedelta(hours=7))

    def test_past_expiry_is_rejected(self) -> None:
        token = self.service.auth.login("eng", "eng-pass-123")
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.service.db.execute(
            "UPDATE sessions SET expires_at=? WHERE token=?", (past, token)
        )
        self.service.db.commit()
        with self.assertRaises(PermissionError):
            self.service.auth.current(token)

    def test_legacy_naive_expiry_is_treated_as_utc(self) -> None:
        future_naive = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        past_naive = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        self.service.db.execute(
            "INSERT INTO sessions VALUES('tok-future','eng',?,1)", (future_naive,)
        )
        self.service.db.execute(
            "INSERT INTO sessions VALUES('tok-past','eng',?,1)", (past_naive,)
        )
        self.service.db.commit()
        self.assertEqual(self.service.auth.current("tok-future").user_id, "eng")
        with self.assertRaises(PermissionError):
            self.service.auth.current("tok-past")

    def test_parse_utc_normalizes_offsets(self) -> None:
        # 同一时刻的不同时区表示必须解析为相同的 UTC 绝对时刻。
        utc = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(_parse_utc("2026-09-24T08:00:00-04:00"), utc)
        self.assertEqual(_parse_utc("2026-09-24T20:00:00+08:00"), utc)
        self.assertEqual(_parse_utc("2026-09-24 12:00:00"), utc)


class DeactivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PhotonService()
        self.service.bootstrap_admin("admin", "admin-pass-1")
        self.service.auth.create_user("eng", "eng-pass-123", "engineer")

    def test_deactivation_invalidates_existing_sessions_immediately(self) -> None:
        token = self.service.auth.login("eng", "eng-pass-123")
        self.assertEqual(self.service.auth.current(token).user_id, "eng")
        admin = self.service.auth.login("admin", "admin-pass-1")
        self.service.deactivate_user(admin, "eng")
        with self.assertRaises(PermissionError):
            self.service.auth.current(token)
        with self.assertRaises(PermissionError):
            self.service.auth.login("eng", "eng-pass-123")

    def test_non_admin_cannot_deactivate(self) -> None:
        other = self.service.auth.login("eng", "eng-pass-123")
        self.service.auth.create_user("eng2", "eng2-pass-12", "engineer")
        with self.assertRaises(PermissionError):
            self.service.deactivate_user(other, "eng2")
        # eng2 仍可登录，证明停用未发生。
        self.assertTrue(self.service.auth.login("eng2", "eng2-pass-12"))

    def test_deactivation_propagates_to_batch_reads(self) -> None:
        admin = self.service.auth.login("admin", "admin-pass-1")
        token = self.service.auth.login("eng", "eng-pass-123")
        self.service.create_lot(token, "L1", "sensor", "P1", 3)
        self.assertEqual(self.service.get_lot(token, "L1")["lot_id"], "L1")
        self.service.deactivate_user(admin, "eng")
        with self.assertRaises(PermissionError):
            self.service.get_lot(token, "L1")


class RestartPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.tmp.close()
        self.path = self.tmp.name
        first = PhotonService(self.path)
        first.bootstrap_admin("admin", "admin-pass-1")
        first.auth.create_user("eng", "eng-pass-123", "engineer")
        self.admin = first.auth.login("admin", "admin-pass-1")
        self.eng = first.auth.login("eng", "eng-pass-123")
        self.expiry = first.db.execute(
            "SELECT expires_at FROM sessions WHERE token=?", (self.eng,)
        ).fetchone()[0]
        first.create_lot(self.eng, "L1", "sensor", "P1", 3)
        first.db.close()

    def tearDown(self) -> None:
        Path(self.path).unlink(missing_ok=True)

    def test_surviving_session_honours_database_expiry_after_restart(self) -> None:
        restarted = PhotonService(self.path)
        # 重启前签发、未过期的令牌仍按数据库中的过期时间有效。
        self.assertEqual(restarted.get_lot(self.eng, "L1")["lot_id"], "L1")
        self.assertEqual(restarted.get_lot(self.admin, "L1")["lot_id"], "L1")
        restarted.db.close()

    def test_expired_session_rejected_after_restart(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute(
            "UPDATE sessions SET expires_at=? WHERE token=?",
            ("2020-01-01T00:00:00+00:00", self.eng),
        )
        conn.commit()
        conn.close()
        restarted = PhotonService(self.path)
        with self.assertRaises(PermissionError):
            restarted.get_lot(self.eng, "L1")
        restarted.db.close()

    def test_deactivation_survives_restart(self) -> None:
        PhotonService(self.path).auth.deactivate("eng")
        restarted = PhotonService(self.path)
        with self.assertRaises(PermissionError):
            restarted.auth.current(self.eng)
        with self.assertRaises(PermissionError):
            restarted.auth.login("eng", "eng-pass-123")
        restarted.db.close()


if __name__ == "__main__":
    unittest.main()
