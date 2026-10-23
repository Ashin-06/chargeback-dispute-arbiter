"""
FastAPI Service for Cryptographic Chargeback Evidence Compiler, Friendly-Fraud (Visa CE 3.0)
Arbiter & Expected-Value Representment Optimizer (port 8014).

Endpoints:
  - GET  /                   : Interactive Web Console (`web/console.html`)
  - POST /disputes/evaluate  : Evaluate a chargeback dispute & compile Representment Brief
  - POST /receipts/verify    : Verify Ed25519 signature & SHA-256 Merkle proofs of an EvidencePacket
  - GET  /disputes           : List sample & evaluated disputes across all 4 categories
  - GET  /bench              : Run the 300-dispute synthetic benchmark
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from disputearb.arbiter import ChargebackArbiter, DisputeClaim
from disputearb.bench import generate_synthetic_disputes, run_benchmark
from disputearb.receipts import EvidencePacket, verify_evidence_packet
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

# Preload representative disputes across all 4 categories for interactive exploration
_ALL_CASES, _DEFAULT_SIGNER = generate_synthetic_disputes(num_cases=300, seed=20261014)
_DEFAULT_ARBITER = ChargebackArbiter(trusted_public_key_hex=_DEFAULT_SIGNER.public_key_hex)


def _build_initial_dispute_store() -> List[Dict[str, Any]]:
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
    records: List[Dict[str, Any]] = []
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


_DISPUTE_STORE: List[Dict[str, Any]] = _build_initial_dispute_store()


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<html><body><h1>DisputeArb Console</h1><p>web/console.html not found.</p></body></html>"
    )


@app.get("/disputes")
def list_disputes(limit: int = 50) -> Dict[str, Any]:
    items = _DISPUTE_STORE[: max(1, min(limit, len(_DISPUTE_STORE)))]
    return {
        "count": len(items),
        "trusted_public_key_hex": _DEFAULT_SIGNER.public_key_hex,
        "reason_codes": {k: v.to_dict() for k, v in REASON_CODE_CATALOG.items()},
        "disputes": items,
    }


@app.post("/receipts/verify")
def verify_receipt_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify an EvidencePacket's Ed25519 signature and SHA-256 Merkle inclusion proofs.
    Accepts either `{"packet": {...}, "trusted_public_key_hex": "..."}` or the
    `EvidencePacket` fields directly at the top level.
    """
    try:
        packet_data = payload["packet"] if "packet" in payload else payload
        trusted_pub = payload.get("trusted_public_key_hex")
        packet = EvidencePacket.from_dict(packet_data)
        res = verify_evidence_packet(packet, trusted_public_key_hex=trusted_pub)
        return res.to_dict()
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid EvidencePacket payload: {exc}") from exc


@app.post("/disputes/evaluate")
def evaluate_dispute_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate an incoming chargeback claim against a cryptographic EvidencePacket
    and optional historical transaction ledger.
    """
    try:
        claim_data = payload["claim"]
        packet_data = payload["packet"]
        ledger_data = payload.get("historical_ledger", [])
        trusted_pub = payload.get("trusted_public_key_hex")

        claim = DisputeClaim.from_dict(claim_data)
        packet = EvidencePacket.from_dict(packet_data)
        ledger = [HistoricalTransaction.from_dict(item) for item in ledger_data]

        arbiter = ChargebackArbiter(trusted_public_key_hex=trusted_pub)
        decision = arbiter.evaluate_dispute(claim, packet, historical_ledger=ledger)
        out = decision.to_dict()

        _DISPUTE_STORE.insert(
            0,
            {
                "case_id": claim.dispute_id,
                "ground_truth_category": decision.classification,
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


@app.get("/bench")
def get_benchmark(num_cases: int = 300) -> Dict[str, Any]:
    return run_benchmark(num_cases=num_cases, seed=20261014)
