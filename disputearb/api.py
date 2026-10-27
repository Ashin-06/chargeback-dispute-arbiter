"""
FastAPI Service for Cryptographic Chargeback Evidence Compiler, Friendly-Fraud (Visa CE 3.0)
Arbiter & Expected-Value Representment Optimizer (port 8014).

Endpoints (permission in brackets):
  - GET  /                         : Interactive Web Console (`web/console.html`)
  - GET  /healthz, /readyz         : Liveness and readiness
  - GET  /metrics                  : Prometheus metrics [metrics]
  - POST /disputes/evaluate        : Evaluate a chargeback and compile a representment brief; stored [evaluate]
  - POST /receipts/verify          : Verify an EvidencePacket's Ed25519 signature and Merkle proofs [evaluate]
  - GET  /disputes                 : Stored disputes, newest first [read]
  - GET  /disputes/{ref}           : One stored dispute with its review history [read]
  - POST /disputes/{ref}/review    : Record what was done (represented, written off, refunded) [review]
  - GET  /bench                    : Run the synthetic benchmark (CPU-heavy) [bench]

Evidence is checked against the merchant's public key only: DISPUTEARB_MERCHANT_PUBLIC_KEY (64 hex
characters). Production requires it and refuses to hold the merchant's signing key. In development,
without it, a demo key (DISPUTEARB_SIGNING_KEY seed or a random one) signs the bundled sample disputes.

Callers send an API key (X-API-Key or Authorization: Bearer); its role decides the permissions.
Settings: ops.py and docs/runbook.md.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from disputearb import db, ops
from disputearb.arbiter import ChargebackArbiter, DisputeClaim
from disputearb.bench import generate_synthetic_disputes, run_benchmark
from disputearb.receipts import EvidencePacket, MerchantSigner, verify_evidence_packet
from disputearb.rules import REASON_CODE_CATALOG, HistoricalTransaction
from disputearb.store import DisputeStore

settings = ops.load_settings()
ops.setup_logging(settings.log_level)

_PUBLIC_HEX = os.environ.get("DISPUTEARB_MERCHANT_PUBLIC_KEY", "").strip().lower()
_SEED_HEX = os.environ.get("DISPUTEARB_SIGNING_KEY", "").strip()
if settings.production:
    if not _PUBLIC_HEX:
        raise ops.ConfigError("production needs DISPUTEARB_MERCHANT_PUBLIC_KEY: the merchant's Ed25519 public key (64 hex)")
    if _SEED_HEX:
        raise ops.ConfigError("production must not hold the merchant's signing key: unset DISPUTEARB_SIGNING_KEY")
if _PUBLIC_HEX:
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", _PUBLIC_HEX):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(_PUBLIC_HEX))
    except ValueError:
        raise ops.ConfigError("DISPUTEARB_MERCHANT_PUBLIC_KEY must be 64 hex characters of an Ed25519 public key") from None

store = DisputeStore(db.connect(settings.database_url))

app = FastAPI(
    title="Cryptographic Chargeback Dispute Arbiter (Visa CE 3.0 & EV Optimizer)",
    version="1.0.0",
    description=(
        "Ed25519 + SHA-256 Merkle Receipt Compiler, Visa CE 3.0 Friendly-Fraud Arbiter, "
        "and Expected-Value Representment Optimizer."
    ),
)
ops.install(app, settings, {"database": lambda: store.db.connect().close()})

WEB_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"

# Representative demo disputes across all 4 categories (development only)
_SAMPLE_INDICES = [0, 1, 2, 65, 66, 67, 68, 69, 70, 71, 72, 135, 136, 137, 201, 202, 204, 255, 256, 259]


def _record(case_id: str, ground_truth: Optional[str], ce30: bool, tamper: str, claim, packet, ledger, decision) -> dict:
    return {
        "case_id": case_id,
        "ground_truth_category": ground_truth,
        "is_ce30_friendly_fraud": ce30,
        "tamper_mode": tamper,
        "claim": claim.to_dict(),
        "packet": packet.to_dict(),
        "historical_ledger": [h.to_dict() for h in ledger],
        "decision": decision.to_dict(),
    }


if _PUBLIC_HEX:
    TRUSTED_PUBLIC_KEY = _PUBLIC_HEX
else:
    _cases, _demo_signer = generate_synthetic_disputes(
        num_cases=300, seed=20261014, signer=MerchantSigner.from_seed_hex(_SEED_HEX) if _SEED_HEX else None
    )
    TRUSTED_PUBLIC_KEY = _demo_signer.public_key_hex
ARBITER = ChargebackArbiter(trusted_public_key_hex=TRUSTED_PUBLIC_KEY)

if not _PUBLIC_HEX and store.count() == 0:  # development: seed the console's sample disputes once
    for i in _SAMPLE_INDICES:
        c = _cases[i]
        dec = ARBITER.evaluate_dispute(c.claim, c.packet, historical_ledger=c.historical_ledger)
        store.record("demo-seed", _record(c.case_id, c.ground_truth_category, c.is_ce30_friendly_fraud, c.tamper_mode,
                                          c.claim, c.packet, c.historical_ledger, dec))


class ReviewRequest(BaseModel):
    status: Literal["open", "represented", "written_off", "refunded"]
    note: str = Field(..., min_length=2, max_length=2000)


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<html><body><h1>DisputeArb Console</h1><p>web/console.html not found.</p></body></html>"
    )


@app.get("/disputes", dependencies=[Depends(ops.require("read"))])
def list_disputes(limit: int = Query(50, ge=1, le=1000),
                  status: Optional[Literal["open", "represented", "written_off", "refunded"]] = None) -> Dict[str, Any]:
    items = store.list(status, limit)
    return {
        "count": len(items),
        "trusted_public_key_hex": TRUSTED_PUBLIC_KEY,
        "reason_codes": {k: v.to_dict() for k, v in REASON_CODE_CATALOG.items()},
        "disputes": items,
    }


@app.get("/disputes/{ref}", dependencies=[Depends(ops.require("read"))])
def get_dispute(ref: str) -> Dict[str, Any]:
    row = store.get(ref[:64])
    if row is None:
        raise HTTPException(404, "dispute not found")
    return row


@app.post("/disputes/{ref}/review")
def review_dispute(ref: str, body: ReviewRequest, ident: dict = Depends(ops.require("review"))) -> Dict[str, Any]:
    row = store.review(ref[:64], ident["user"] or "demo", body.status, body.note)
    if row is None:
        raise HTTPException(404, "dispute not found")
    ops.DECISIONS.labels(decision=f"review_{body.status}").inc()
    return row


@app.post("/receipts/verify", dependencies=[Depends(ops.require("evaluate"))])
def verify_receipt_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify an EvidencePacket's Ed25519 signature (against the merchant key) and
    SHA-256 Merkle inclusion proofs. Accepts `{"packet": {...}}` or the packet fields directly.
    """
    try:
        packet_data = payload["packet"] if "packet" in payload else payload
        packet = EvidencePacket.from_dict(packet_data)
        res = verify_evidence_packet(packet, trusted_public_key_hex=TRUSTED_PUBLIC_KEY)
        return res.to_dict()
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=_why(exc, "evidence packet")) from None


@app.post("/disputes/evaluate")
def evaluate_dispute_endpoint(payload: Dict[str, Any], ident: dict = Depends(ops.require("evaluate"))) -> Dict[str, Any]:
    """
    Evaluate an incoming chargeback claim against a cryptographic EvidencePacket
    and optional historical transaction ledger.
    """
    try:
        claim = DisputeClaim.from_dict(payload["claim"])
        packet = EvidencePacket.from_dict(payload["packet"])
        ledger = [HistoricalTransaction.from_dict(item) for item in payload.get("historical_ledger", [])]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=_why(exc, "dispute")) from None

    # Never take the trusted key from the caller: they could vouch for their own forgery
    decision = ARBITER.evaluate_dispute(claim, packet, historical_ledger=ledger)
    out = decision.to_dict()
    ops.DECISIONS.labels(decision=decision.recommended_action).inc()
    out["dispute_ref"] = store.record(ident["user"] or "demo", _record(
        claim.dispute_id, None, decision.rule_report.ce30.qualified,
        "none" if decision.verification.valid else "detected_tampering", claim, packet, ledger, decision))
    return out


def _why(exc: Exception, what: str) -> str:
    """Say which field was wrong without echoing the submitted value."""
    if isinstance(exc, KeyError):
        return f"invalid {what}: missing field {exc.args[0]!r}"[:200]
    return f"invalid {what}: a field has the wrong type or value"


@app.get("/bench", dependencies=[Depends(ops.require("bench"))])
def get_benchmark(num_cases: int = Query(300, ge=10, le=2000)) -> Dict[str, Any]:
    return run_benchmark(num_cases=num_cases, seed=20261014)
