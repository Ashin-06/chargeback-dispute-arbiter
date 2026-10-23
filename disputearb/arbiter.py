"""
Chargeback Dispute Arbiter & Representment Evidence Brief Compiler.

Evaluates incoming chargeback claims against cryptographic EvidencePackets and
historical transaction ledgers:
  1. Verifies Ed25519 signature and SHA-256 Merkle inclusion proofs (`receipts.py`).
  2. Evaluates Visa CE 3.0 and card-network/UPI reason-code rules (`rules.py`).
  3. Classifies into:
     - `first_party_friendly_fraud`
     - `true_third_party_fraud`
     - `merchant_fulfillment_fault`
     - `tampered_evidence_rejected`
  4. Runs the Expected-Value Representment Optimizer (`optimizer.py`).
  5. Compiles a structured Markdown + JSON Representment Evidence Brief citing
     exact Merkle leaf hashes and CE 3.0 historical match IDs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from disputearb.optimizer import EVOptimizationResult, optimize_representment_decision
from disputearb.receipts import EvidencePacket, VerificationResult, as_amount, verify_evidence_packet
from disputearb.rules import (
    HistoricalTransaction,
    RuleEvaluationReport,
    evaluate_reason_code_rules,
)

CLASS_FRIENDLY_FRAUD = "first_party_friendly_fraud"
CLASS_TRUE_FRAUD = "true_third_party_fraud"
CLASS_MERCHANT_FAULT = "merchant_fulfillment_fault"
CLASS_TAMPERED_REJECTED = "tampered_evidence_rejected"


@dataclass
class DisputeClaim:
    dispute_id: str
    txn_id: str
    reason_code: str
    amount_inr: float
    cardholder_statement: str
    network_arbitration_fee_inr: Optional[float] = None
    representment_filing_fee_inr: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DisputeClaim":
        return cls(
            dispute_id=str(data["dispute_id"]),
            txn_id=str(data["txn_id"]),
            reason_code=str(data["reason_code"]),
            amount_inr=as_amount(data["amount_inr"]),
            cardholder_statement=str(data.get("cardholder_statement", "")),
            network_arbitration_fee_inr=(
                as_amount(data["network_arbitration_fee_inr"])
                if data.get("network_arbitration_fee_inr") is not None
                else None
            ),
            representment_filing_fee_inr=(
                as_amount(data["representment_filing_fee_inr"])
                if data.get("representment_filing_fee_inr") is not None
                else None
            ),
        )


@dataclass
class RepresentmentBrief:
    dispute_id: str
    txn_id: str
    reason_code: str
    classification: str
    recommended_action: str
    merkle_root: str
    ed25519_signature: str
    leaf_hashes: Dict[str, str]
    ce30_qualifying_txn_ids: List[str]
    markdown_brief: str
    structured_json: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "txn_id": self.txn_id,
            "reason_code": self.reason_code,
            "classification": self.classification,
            "recommended_action": self.recommended_action,
            "merkle_root": self.merkle_root,
            "ed25519_signature": self.ed25519_signature,
            "leaf_hashes": dict(self.leaf_hashes),
            "ce30_qualifying_txn_ids": list(self.ce30_qualifying_txn_ids),
            "markdown_brief": self.markdown_brief,
            "structured_json": self.structured_json,
        }


@dataclass
class ArbitrationDecision:
    dispute_id: str
    txn_id: str
    reason_code: str
    classification: str
    recommended_action: str
    verification: VerificationResult
    rule_report: RuleEvaluationReport
    ev_optimization: EVOptimizationResult
    representment_brief: RepresentmentBrief

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "txn_id": self.txn_id,
            "reason_code": self.reason_code,
            "classification": self.classification,
            "recommended_action": self.recommended_action,
            "verification": self.verification.to_dict(),
            "rule_report": self.rule_report.to_dict(),
            "ev_optimization": self.ev_optimization.to_dict(),
            "representment_brief": self.representment_brief.to_dict(),
        }


def classify_dispute(
    claim: DisputeClaim,
    packet: EvidencePacket,
    verification: VerificationResult,
    rule_report: RuleEvaluationReport,
) -> str:
    """
    Classify an incoming dispute into one of:
      - `tampered_evidence_rejected`
      - `merchant_fulfillment_fault`
      - `first_party_friendly_fraud`
      - `true_third_party_fraud`
    """
    if not verification.valid:
        return CLASS_TAMPERED_REJECTED

    rc = claim.reason_code
    auth = packet.checkout_auth
    delivery = packet.delivery_proof

    # Check explicit merchant fulfillment or billing faults first
    if rc == "13.1" or rc == "4853" or rc == "U14":
        if not delivery.delivered:
            return CLASS_MERCHANT_FAULT
        if rule_report.otp_delivery_verified and rule_report.gps_and_signature_present:
            return CLASS_FRIENDLY_FRAUD
        if rule_report.post_purchase_same_device_or_ip_count >= 1 and delivery.delivered:
            return CLASS_FRIENDLY_FRAUD
        return CLASS_MERCHANT_FAULT

    if rc == "13.3":
        if not delivery.delivered or not delivery.as_described_qc_passed:
            return CLASS_MERCHANT_FAULT
        if (
            delivery.as_described_qc_passed
            and rule_report.otp_delivery_verified
            and rule_report.post_purchase_same_device_or_ip_count >= 1
        ):
            return CLASS_FRIENDLY_FRAUD
        return CLASS_MERCHANT_FAULT

    if rc == "13.6":
        if auth.credit_refund_processed and auth.credit_arn:
            return CLASS_FRIENDLY_FRAUD
        if rule_report.otp_delivery_verified and not auth.cancelled_before_billing:
            return CLASS_FRIENDLY_FRAUD
        return CLASS_MERCHANT_FAULT

    if rc == "13.7":
        if auth.cancelled_before_billing:
            return CLASS_MERCHANT_FAULT
        if not auth.cancelled_before_billing and rule_report.post_purchase_same_device_or_ip_count >= 1:
            return CLASS_FRIENDLY_FRAUD
        return CLASS_MERCHANT_FAULT

    # Fraud reason codes (10.4, 4837, U10, or generic)
    if not delivery.delivered and not rule_report.ce30.qualified and not rule_report.liability_shift_eci05:
        # Check if merchant simply never fulfilled the order on a consumer dispute
        if rule_report.spec.category == "CONSUMER_DISPUTE":
            return CLASS_MERCHANT_FAULT

    # First-party friendly fraud indicators on fraud reason codes:
    #   (a) Visa CE 3.0 qualified (>=2 undisputed prior txns aged 120-365d matching >=2 core elements)
    #   (b) 3DS2 ECI 05 liability shift + OTP-verified delivery + post-purchase usage
    #   (c) 3DS2 ECI 05 + OTP-verified delivery
    if rule_report.ce30.qualified:
        return CLASS_FRIENDLY_FRAUD

    if (
        rule_report.liability_shift_eci05
        and rule_report.otp_delivery_verified
        and (rule_report.post_purchase_same_device_or_ip_count >= 1 or rule_report.gps_and_signature_present)
    ):
        return CLASS_FRIENDLY_FRAUD

    if (
        rule_report.three_ds_authenticated
        and rule_report.otp_delivery_verified
        and rule_report.post_purchase_same_device_or_ip_count >= 2
    ):
        return CLASS_FRIENDLY_FRAUD

    return CLASS_TRUE_FRAUD


def compile_representment_brief(
    claim: DisputeClaim,
    packet: EvidencePacket,
    verification: VerificationResult,
    rule_report: RuleEvaluationReport,
    ev_opt: EVOptimizationResult,
    classification: str,
) -> RepresentmentBrief:
    """
    Compile a structured Markdown & JSON Representment Evidence Brief citing exact
    SHA-256 Merkle leaf hashes, Ed25519 signature, and Visa CE 3.0 historical match IDs.
    """
    leaves = packet.leaf_hashes
    ce30_ids = rule_report.ce30.qualifying_txn_ids
    ce30_matches_dict = [m.to_dict() for m in rule_report.ce30.matches]

    md_lines = [
        f"# Representment Evidence Brief — `{claim.dispute_id}`",
        "",
        "## 1. Dispute & Arbitration Summary",
        f"- **Dispute ID:** `{claim.dispute_id}`",
        f"- **Transaction ID:** `{claim.txn_id}`",
        f"- **Network & Reason Code:** `{rule_report.spec.network}` `{claim.reason_code}` ({rule_report.spec.title})",
        f"- **Disputed Amount:** ₹{claim.amount_inr:,.2f}",
        f"- **Arbiter Classification:** `{classification}`",
        f"- **Recommended Action:** `{ev_opt.recommended_action}`",
        f"- **Estimated Win Probability $P(\\text{{win}})$ (rule weights, not calibrated):** `{ev_opt.win_probability:.2%}`",
        f"- **Expected Net Recovery $\\mathbb{{E}}[\\text{{Net}}]$:** `₹{ev_opt.expected_net_recovery_inr:,.2f}` "
        f"(Arbitration Fee: ₹{ev_opt.network_arbitration_fee_inr:,.0f}, Filing Fee: ₹{ev_opt.representment_filing_fee_inr:,.0f})",
        "",
        "## 2. Cryptographic Evidence Integrity (Ed25519 + SHA-256 Merkle Tree)",
        f"- **Verification Status:** `{'VALID' if verification.valid else 'TAMPERED / INVALID'}` ({verification.reason})",
        f"- **Merkle Root (SHA-256):** `{packet.merkle_root}`",
        f"- **Ed25519 Signature:** `{packet.ed25519_signature}`",
        f"- **Merchant Public Key:** `{packet.public_key_hex}`",
        f"- **Leaf 1 (`checkout_auth`) Hash:** `{leaves.get('checkout_auth', '')}`",
        f"- **Leaf 2 (`delivery_proof`) Hash:** `{leaves.get('delivery_proof', '')}`",
        f"- **Leaf 3 (`post_purchase_usage`) Hash:** `{leaves.get('post_purchase_usage', '')}`",
        "",
        "## 3. Visa Compelling Evidence 3.0 (CE 3.0) & Rule Evaluation",
        f"- **CE 3.0 Qualified:** `{rule_report.ce30.qualified}`",
        f"- **CE 3.0 Historical Match IDs:** `{', '.join(ce30_ids) if ce30_ids else 'None'}`",
        f"- **CE 3.0 Shared Core Elements:** `{', '.join(rule_report.ce30.shared_elements_union) if rule_report.ce30.shared_elements_union else 'None'}`",
        f"- **3DS2 Authentication:** `status={packet.checkout_auth.three_ds_status}`, `ECI={packet.checkout_auth.eci}`, `CAVV={packet.checkout_auth.cavv}`",
        f"- **Fulfillment & Delivery Proof:** `delivered={packet.delivery_proof.delivered}`, `OTP={packet.delivery_proof.otp_verified_handoff}`, `GPS={packet.delivery_proof.carrier_signed_gps}`",
        f"- **Post-Purchase Authenticated Sessions:** `{rule_report.post_purchase_same_device_or_ip_count}` matching device/IP event(s)",
        "",
        "## 4. Key Findings & Rebuttal Rationale",
    ]
    for finding in rule_report.rule_findings:
        md_lines.append(f"- {finding}")
    md_lines.append(f"- **Economic Decision Rationale:** {ev_opt.rationale}")

    markdown_brief = "\n".join(md_lines)

    structured_json: Dict[str, Any] = {
        "dispute_id": claim.dispute_id,
        "txn_id": claim.txn_id,
        "network": rule_report.spec.network,
        "reason_code": claim.reason_code,
        "reason_title": rule_report.spec.title,
        "amount_inr": claim.amount_inr,
        "classification": classification,
        "recommended_action": ev_opt.recommended_action,
        "win_probability": ev_opt.win_probability,
        "expected_net_recovery_inr": round(ev_opt.expected_net_recovery_inr, 2),
        "cryptographic_proof": {
            "verified": verification.valid,
            "merkle_root": packet.merkle_root,
            "ed25519_signature": packet.ed25519_signature,
            "public_key_hex": packet.public_key_hex,
            "leaf_hashes": dict(leaves),
            "tampered_leaves": list(verification.tampered_leaves),
        },
        "ce30_evidence": {
            "qualified": rule_report.ce30.qualified,
            "qualifying_txn_ids": list(ce30_ids),
            "matches": ce30_matches_dict,
            "shared_elements": list(rule_report.ce30.shared_elements_union),
        },
        "telemetry_summary": {
            "three_ds_status": packet.checkout_auth.three_ds_status,
            "eci": packet.checkout_auth.eci,
            "device_id": packet.checkout_auth.device_id,
            "ip_address": packet.checkout_auth.ip_address,
            "otp_verified_handoff": packet.delivery_proof.otp_verified_handoff,
            "carrier_signed_gps": packet.delivery_proof.carrier_signed_gps,
            "post_purchase_matching_sessions": rule_report.post_purchase_same_device_or_ip_count,
        },
    }

    return RepresentmentBrief(
        dispute_id=claim.dispute_id,
        txn_id=claim.txn_id,
        reason_code=claim.reason_code,
        classification=classification,
        recommended_action=ev_opt.recommended_action,
        merkle_root=packet.merkle_root,
        ed25519_signature=packet.ed25519_signature,
        leaf_hashes=dict(leaves),
        ce30_qualifying_txn_ids=list(ce30_ids),
        markdown_brief=markdown_brief,
        structured_json=structured_json,
    )


class ChargebackArbiter:
    """End-to-end cryptographic chargeback arbiter and EV representment optimizer."""

    def __init__(self, trusted_public_key_hex: str) -> None:
        # The merchant key evidence must be signed with; see verify_evidence_packet
        self.trusted_public_key_hex = trusted_public_key_hex

    def evaluate_dispute(
        self,
        claim: DisputeClaim,
        packet: EvidencePacket,
        historical_ledger: Optional[List[HistoricalTransaction]] = None,
    ) -> ArbitrationDecision:
        verification = verify_evidence_packet(
            packet, trusted_public_key_hex=self.trusted_public_key_hex
        )
        rule_report = evaluate_reason_code_rules(
            claim.reason_code, packet, historical_ledger=historical_ledger
        )
        classification = classify_dispute(claim, packet, verification, rule_report)
        ev_opt = optimize_representment_decision(
            classification=classification,
            amount_inr=claim.amount_inr,
            rule_report=rule_report,
            verification=verification,
            network_arbitration_fee_inr=claim.network_arbitration_fee_inr,
            representment_filing_fee_inr=claim.representment_filing_fee_inr,
        )
        brief = compile_representment_brief(
            claim=claim,
            packet=packet,
            verification=verification,
            rule_report=rule_report,
            ev_opt=ev_opt,
            classification=classification,
        )
        return ArbitrationDecision(
            dispute_id=claim.dispute_id,
            txn_id=claim.txn_id,
            reason_code=claim.reason_code,
            classification=classification,
            recommended_action=ev_opt.recommended_action,
            verification=verification,
            rule_report=rule_report,
            ev_optimization=ev_opt,
            representment_brief=brief,
        )
