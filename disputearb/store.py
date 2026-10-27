"""Evaluated disputes and what analysts did with them, kept in the database (see db.py).
Amounts are stored as integer paise; the JSON record keeps them as decimal strings."""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.engine import Engine

# open: awaiting a decision; represented: evidence submitted to the network;
# written_off: accepted the loss; refunded: refunded before or during the dispute
STATUSES = ("open", "represented", "written_off", "refunded")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class DisputeStore:
    def __init__(self, engine: Engine):
        self.db = engine
        self._lock = threading.Lock()

    def count(self) -> int:
        with self.db.connect() as c:
            return c.execute(text("SELECT COUNT(*) FROM disputes")).scalar()

    def record(self, user: str, rec: dict) -> str:
        ref = uuid.uuid4().hex
        claim, decision = rec["claim"], rec["decision"]
        paise = int(Decimal(claim["amount_inr"]) * 100)
        with self._lock, self.db.begin() as c:
            c.execute(text("INSERT INTO disputes (id, created_at, requested_by, dispute_id, reason_code, amount_paise, "
                           "classification, recommended_action, status, record) "
                           "VALUES (:i, :t, :u, :d, :rc, :a, :cl, :ac, 'open', :r)"),
                      {"i": ref, "t": _now(), "u": user, "d": claim["dispute_id"], "rc": claim["reason_code"], "a": paise,
                       "cl": decision["classification"], "ac": decision["recommended_action"],
                       "r": json.dumps(rec, default=str)})
        return ref

    @staticmethod
    def _row(r) -> dict:
        return {"id": r.id, "created_at": r.created_at, "requested_by": r.requested_by, "status": r.status,
                "amount_paise": r.amount_paise, **json.loads(r.record)}

    def list(self, status: str | None = None, limit: int = 50) -> list[dict]:
        sql, args = "SELECT * FROM disputes", {"n": limit}
        if status:
            sql, args["st"] = sql + " WHERE status = :st", status
        with self.db.connect() as c:
            return [self._row(r) for r in c.execute(text(sql + " ORDER BY created_at DESC, id LIMIT :n"), args)]

    def get(self, ref: str) -> dict | None:
        with self.db.connect() as c:
            r = c.execute(text("SELECT * FROM disputes WHERE id = :i"), {"i": ref}).first()
            if r is None:
                return None
            reviews = c.execute(text("SELECT reviewed_at, reviewer, status, note FROM dispute_reviews "
                                     "WHERE dispute_ref = :i ORDER BY reviewed_at"), {"i": ref}).mappings().all()
        return {**self._row(r), "reviews": [dict(x) for x in reviews]}

    def review(self, ref: str, reviewer: str, status: str, note: str) -> dict | None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self._lock, self.db.begin() as c:
            if c.execute(text("UPDATE disputes SET status = :s WHERE id = :i"), {"s": status, "i": ref}).rowcount == 0:
                return None
            c.execute(text("INSERT INTO dispute_reviews (dispute_ref, reviewed_at, reviewer, status, note) "
                           "VALUES (:i, :t, :r, :s, :n)"), {"i": ref, "t": _now(), "r": reviewer, "s": status, "n": note})
        return self.get(ref)
