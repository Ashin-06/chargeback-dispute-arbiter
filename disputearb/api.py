"""
FastAPI Service for Cryptographic Chargeback Evidence Compiler, Friendly-Fraud (Visa CE 3.0)
Arbiter & Expected-Value Representment Optimizer (port 8014).

Endpoints:
  - GET  /                   : Interactive Web Console (`web/console.html`)
  - POST /disputes/evaluate  : Evaluate a chargeback dispute & compile Representment Brief
  - POST /receipts/verify    : Verify Ed25519 signature & SHA-256 Merkle proofs of an EvidencePacket
  - GET  /disputes           : List sample & evaluated disputes across all 4 categories
  - GET  /bench              : Run the 300-dispute synthetic benchmark

Evidence is checked against this server's merchant key only: DISPUTEARB_SIGNING_KEY (64 hex
characters, the Ed25519 private seed) or, if unset, a random key made at start-up.

Set DISPUTEARB_API_KEY to require it in the X-API-Key header on every endpoint except / (unset =
open, for local use; `python -m disputearb serve` refuses a non-loopback host without it).
"""

from __future__ import annotations

import hmac
import os
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from disputearb.arbiter import ChargebackArbiter, DisputeClaim
from disputearb.bench import generate_synthetic_disputes, run_benchmark
from disputearb.receipts import EvidencePacket, MerchantSigner, verify_evidence_packet
from disputearb.rules import REASON_CODE_CATALOG, HistoricalTransaction

app = FastAPI(
    title="Cryptographic Chargeback Dispute Arbiter (Visa CE 3.0 & EV Optimizer)",
    version="1.0.0",
    description=(
        "Ed25519 + SHA-256 Merkle Receipt Compiler, Visa CE 3.0 Friendly-Fraud Arbiter, "
        "and Expected-Value Representment Optimizer."
    ),
)

WEB_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
API_KEY = os.environ.get("DISPUTEARB_API_KEY")
MAX_BODY_BYTES = 1_000_000
MAX_STORED_DISPUTES = 200  # evaluated disputes kept for the console; oldest are dropped


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and not hmac.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(401, "missing or wrong X-API-Key")


@app.middleware("http")
async def limit_body(request: Request, call_next):
    if request.method == "POST":
        length = request.headers.get("content-length", "")
        if not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "body missing Content-Length or over 1 MB"}, status_code=413)
    return await call_next(request)

# Preload representative disputes across all 4 categories for interactive exploration
_SEED_HEX = os.environ.get("DISPUTEARB_SIGNING_KEY")
_ALL_CASES, _DEFAULT_SIGNER = generate_synthetic_disputes(
    num_cases=300,
    seed=20261014,
    signer=MerchantSigner.from_seed_hex(_SEED_HEX) if _SEED_HEX else None,
)
_DEFAULT_ARBITER = ChargebackArbiter(trusted_public_key_hex=_DEFAULT_SIGNER.public_key_hex)


def _build_initial_dispute_store() -> Deque[Dict[str, Any]]:
    # Pick representative cases across all 4 categories and diverse reason codes
    selected_indices = [
        0,    # Visa 10.4 CE 3.0 Friendly Fraud (micro ticket -> write-off)
        1,    # Visa 10.4 CE 3.0 Friendly Fraud (mid ticket -> fight)
        2,    # Visa 10.4 CE 3.0 Friendly Fraud (high ticket -> fight)
        65,   # Visa 13.1 Merchandise Not Received Friendly Fraud
        66,   # Visa 13.3 Not as Described Friendly Fraud
        67,   # Visa 13.6 Credit Not Processed Friendly Fraud
        68,   # Visa 13.7 Cancelled Recurring Friendly Fraud
        69,   # Mastercard 4837 Friendly Fraud
        70,   # Mastercard 4853 Friendly Fraud
        71,   # RuPay/UPI U10 Friendly Fraud
        72,   # RuPay/UPI U14 Friendly Fraud
        135,  # True Third-Party Fraud (Visa 10.4)
        136,  # True Third-Party Fraud (Mastercard 4837)
        137,  # True Third-Party Fraud (RuPay/UPI U10)
        201,  # Merchant Fulfillment Fault (Visa 13.1 Undelivered)
        202,  # Merchant Fulfillment Fault (Visa 13.3 Defective QC failed)
        204,  # Merchant Fulfillment Fault (Visa 13.7 Cancelled prior to billing)
        255,  # Tampered Evidence Rejected (IP tampered)
        256,  # Tampered Evidence Rejected (Device ID tampered)
        259,  # Tampered Evidence Rejected (Recomputed Merkle + forged signature)
    ]
    records: Deque[Dict[str, Any]] = deque(maxlen=MAX_STORED_DISPUTES)
    for i in selected_indices:
        if 0 <= i < len(_ALL_CASES):
            c = _ALL_CASES[i]
            dec = _DEFAULT_ARBITER.evaluate_dispute(
                c.claim, c.packet, historical_ledger=c.historical_ledger
            )
            records.append(
                {
                    "case_id": c.case_id,
                    "ground_truth_category": c.ground_truth_category,
                    "is_ce30_friendly_fraud": c.is_ce30_friendly_fraud,
                    "tamper_mode": c.tamper_mode,
                    "claim": c.claim.to_dict(),
                    "packet": c.packet.to_dict(),
                    "historical_ledger": [h.to_dict() for h in c.historical_ledger],
                    "decision": dec.to_dict(),
                }
            )
    return records


_DISPUTE_STORE: Deque[Dict[str, Any]] = _build_initial_dispute_store()


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<html><body><h1>DisputeArb Console</h1><p>web/console.html not found.</p></body></html>"
    )


@app.get("/disputes", dependencies=[Depends(require_key)])
def list_disputes(limit: int = Query(50, ge=1, le=MAX_STORED_DISPUTES)) -> Dict[str, Any]:
    items = list(_DISPUTE_STORE)[:limit]
    return {
        "count": len(items),
        "trusted_public_key_hex": _DEFAULT_SIGNER.public_key_hex,
        "reason_codes": {k: v.to_dict() for k, v in REASON_CODE_CATALOG.items()},
        "disputes": items,
    }


@app.post("/receipts/verify", dependencies=[Depends(require_key)])
def verify_receipt_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify an EvidencePacket's Ed25519 signature (against this server's merchant key) and
    SHA-256 Merkle inclusion proofs. Accepts `{"packet": {...}}` or the packet fields directly.
    """
    try:
        packet_data = payload["packet"] if "packet" in payload else payload
        packet = EvidencePacket.from_dict(packet_data)
        res = verify_evidence_packet(packet, trusted_public_key_hex=_DEFAULT_SIGNER.public_key_hex)
        return res.to_dict()
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid EvidencePacket payload: {exc}") from exc


@app.post("/disputes/evaluate", dependencies=[Depends(require_key)])
def evaluate_dispute_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate an incoming chargeback claim against a cryptographic EvidencePacket
    and optional historical transaction ledger.
    """
    try:
        claim_data = payload["claim"]
        packet_data = payload["packet"]
        ledger_data = payload.get("historical_ledger", [])

        claim = DisputeClaim.from_dict(claim_data)
        packet = EvidencePacket.from_dict(packet_data)
        ledger = [HistoricalTransaction.from_dict(item) for item in ledger_data]

        # Never take the trusted key from the caller: they could vouch for their own forgery
        decision = _DEFAULT_ARBITER.evaluate_dispute(claim, packet, historical_ledger=ledger)
        out = decision.to_dict()

        _DISPUTE_STORE.appendleft(
            {
                "case_id": claim.dispute_id,
                "ground_truth_category": None,  # unknown for a live dispute; see decision.classification
                "is_ce30_friendly_fraud": decision.rule_report.ce30.qualified,
                "tamper_mode": "none" if decision.verification.valid else "detected_tampering",
                "claim": claim.to_dict(),
                "packet": packet.to_dict(),
                "historical_ledger": [h.to_dict() for h in ledger],
                "decision": out,
            },
        )
        return out
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid dispute evaluation payload: {exc}") from exc


@app.get("/bench", dependencies=[Depends(require_key)])
def get_benchmark(num_cases: int = Query(300, ge=10, le=2000)) -> Dict[str, Any]:
    return run_benchmark(num_cases=num_cases, seed=20261014)
