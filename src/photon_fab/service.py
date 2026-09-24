"""协调认证、批次、测试和放行门禁的应用服务。"""

from __future__ import annotations

import threading
import uuid
from typing import Sequence

from .analytics import confidence_interval, summarize_spectrum, yield_rate
from .auth import Auth
from .storage import connect, event, transaction, utcnow


class PhotonService:
    def __init__(self, database: str = ":memory:"):
        # 单个 SQLite 连接被多个 HTTP 工作线程共享，用可重入锁串行化全部访问
        # （公开方法之间会相互调用，故需 RLock）。
        self.lock = threading.RLock()
        self.db = connect(database)
        self.auth = Auth(self.db, self.lock)

    def bootstrap_admin(self, user_id: str = "admin", password: str = "photon-admin") -> None:
        try:
            self.auth.create_user(user_id, password, "admin")
        except Exception:
            pass

    def deactivate_user(self, actor_token: str, user_id: str) -> None:
        # 仅管理员可停用账号；停用立即令该用户全部会话失效。
        self.auth.require(actor_token, "admin")
        self.auth.deactivate(user_id)

    def create_lot(self, token: str, lot_id: str, product: str, process_rev: str, wafer_count: int) -> dict:
        with self.lock:
            actor = self.auth.require(token, "submit")
            if wafer_count <= 0 or not lot_id.strip() or not process_rev.strip():
                raise ValueError("lot fields are invalid")
            now = utcnow()
            with transaction(self.db):
                self.db.execute("INSERT INTO chip_lots VALUES(?,?,?,?,?,?,?,?)", (lot_id, product, process_rev, wafer_count, "engineering", actor.user_id, now, now))
                event(self.db, lot_id, "created", actor.user_id, {"product": product, "process_rev": process_rev})
            return self.get_lot(token, lot_id)

    def get_lot(self, token: str, lot_id: str) -> dict:
        with self.lock:
            self.auth.require(token, "read")
            row = self.db.execute("SELECT * FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone()
            if not row:
                raise KeyError(lot_id)
            return dict(row)

    def add_measurement(self, token: str, lot_id: str, wavelength_nm: float, response: float, noise: float, instrument: str) -> dict:
        with self.lock:
            actor = self.auth.require(token, "measure")
            measurement_id = uuid.uuid4().hex
            with transaction(self.db):
                if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                    raise KeyError(lot_id)
                self.db.execute("INSERT INTO measurements VALUES(?,?,?,?,?,?,?,?)", (measurement_id, lot_id, float(wavelength_nm), float(response), float(noise), instrument, actor.user_id, utcnow()))
                event(self.db, lot_id, "measurement", actor.user_id, {"measurement_id": measurement_id, "wavelength_nm": wavelength_nm})
            return {"measurement_id": measurement_id, "lot_id": lot_id}

    def analyze(self, token: str, lot_id: str) -> dict:
        with self.lock:
            self.auth.require(token, "analyze")
            rows = self.db.execute("SELECT wavelength_nm,response FROM measurements WHERE lot_id=? ORDER BY wavelength_nm", (lot_id,)).fetchall()
            if len(rows) < 3:
                raise ValueError("three measurements are required")
            summary = summarize_spectrum([r[0] for r in rows], [r[1] for r in rows])
            rates = yield_rate(self.get_lot(token, lot_id)["wafer_count"], sum(1 for r in rows if r[1] >= 0.8), 0)
            ci = confidence_interval([r[1] for r in rows])
            return {"lot_id": lot_id, "spectrum": summary.__dict__, "yield": rates, "response_ci": ci}

    def approve(self, token: str, lot_id: str, decision: str, reason: str) -> dict:
        with self.lock:
            actor = self.auth.require(token, "approve")
            if decision not in {"release", "hold", "reject"} or not reason.strip():
                raise ValueError("decision and reason are required")
            with transaction(self.db):
                self.db.execute("INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?)", (lot_id, actor.user_id, decision, reason, utcnow()))
                status = {"release": "released", "hold": "hold", "reject": "rejected"}[decision]
                self.db.execute("UPDATE chip_lots SET status=?,updated_at=? WHERE lot_id=?", (status, utcnow(), lot_id))
                event(self.db, lot_id, "approval", actor.user_id, {"decision": decision, "reason": reason})
            return self.get_lot(token, lot_id)

    def audit(self, token: str, lot_id: str) -> list[dict]:
        with self.lock:
            self.auth.require(token, "read")
            return [dict(r) for r in self.db.execute("SELECT * FROM lot_events WHERE lot_id=? ORDER BY event_id", (lot_id,)).fetchall()]
