"""
Expected-Value (EV) Representment Optimizer.

Computes calibrated representment win probability P(win | evidence, reason_code)
and Expected Net Recovery:
    E[Net] = P(win) * Amount - (1 - P(win)) * NetworkArbitrationFee - RepresentmentFilingFee

Recommends one of:
  - FIGHT_REPRESENTMENT
  - ACCEPT_WRITE_OFF
  - AUTO_REFUND_PRE_DISPUTE
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from disputearb.receipts import VerificationResult
from disputearb.rules import RuleEvaluationReport

ACTION_FIGHT = "FIGHT_REPRESENTMENT"
ACTION_WRITE_OFF = "ACCEPT_WRITE_OFF"
ACTION_AUTO_REFUND = "AUTO_REFUND_PRE_DISPUTE"


@dataclass
class EVOptimizationResult:
    win_probability: float
    amount_inr: float
    network_arbitration_fee_inr: float
    representment_filing_fee_inr: float
    expected_net_recovery_inr: float
    break_even_amount_inr: float
    recommended_action: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "win_probability": round(self.win_probability, 4),
            "amount_inr": round(self.amount_inr, 2),
            "network_arbitration_fee_inr": round(self.network_arbitration_fee_inr, 2),
            "representment_filing_fee_inr": round(self.representment_filing_fee_inr, 2),
            "expected_net_recovery_inr": round(self.expected_net_recovery_inr, 2),
            "break_even_amount_inr": round(self.break_even_amount_inr, 2),
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
        }


def compute_expected_net_recovery(
    amount_inr: float,
    win_probability: float,
    network_arbitration_fee_inr: float,
    representment_filing_fee_inr: float,
) -> float:
    """
    Compute Expected Net Recovery (INR):
        E[Net] = P(win) * Amount - (1 - P(win)) * NetworkArbitrationFee - RepresentmentFilingFee
    """
    p = max(0.0, min(1.0, float(win_probability)))
    return (
        p * float(amount_inr)
        - (1.0 - p) * float(network_arbitration_fee_inr)
        - float(representment_filing_fee_inr)
    )


def compute_win_probability(
    classification: str,
    rule_report: RuleEvaluationReport,
    verification: VerificationResult,
) -> float:
    """
    Calibrate representment win probability P(win | evidence, reason_code).
    If cryptographic verification fails, win probability is 0.0 because altered/forged
    evidence is rejected before submission.
    """
    if not verification.valid or classification == "tampered_evidence_rejected":
        return 0.0

    rc = rule_report.reason_code
    ce30_ok = rule_report.ce30.qualified
    eci05 = rule_report.liability_shift_eci05
    otp_ok = rule_report.otp_delivery_verified and rule_report.gps_and_signature_present
    usage_cnt = rule_report.post_purchase_same_device_or_ip_count

    if classification == "first_party_friendly_fraud":
        base = 0.72
        if ce30_ok:
            base += 0.16
        if eci05:
            base += 0.08
        if otp_ok:
            base += 0.05
        if usage_cnt >= 1:
            base += 0.03
        if rc == "10.4" and ce30_ok:
            base = max(base, 0.94)
        return min(0.97, round(base, 4))

    if classification == "merchant_fulfillment_fault":
        # Merchant did not fulfill, shipped defective item, or billed after cancellation
        return 0.01

    if classification == "true_third_party_fraud":
        # Unauthenticated card-absent or account-takeover fraud without CE 3.0 or 3DS2 ECI 05
        base = 0.01
        if rule_report.three_ds_authenticated:
            base += 0.05
        if otp_ok:
            base += 0.04
        return min(0.15, round(base, 4))

    return min(0.95, max(0.02, round(rule_report.evidence_strength_score * 0.85, 4)))


def optimize_representment_decision(
    classification: str,
    amount_inr: float,
    rule_report: RuleEvaluationReport,
    verification: VerificationResult,
    network_arbitration_fee_inr: Optional[float] = None,
    representment_filing_fee_inr: Optional[float] = None,
) -> EVOptimizationResult:
    """
    Compute calibrated win probability, expected net recovery in INR, break-even threshold,
    and optimal decision (`FIGHT_REPRESENTMENT`, `ACCEPT_WRITE_OFF`, or `AUTO_REFUND_PRE_DISPUTE`).
    """
    arb_fee = (
        float(network_arbitration_fee_inr)
        if network_arbitration_fee_inr is not None
        else rule_report.spec.default_arbitration_fee_inr
    )
    filing_fee = (
        float(representment_filing_fee_inr)
        if representment_filing_fee_inr is not None
        else rule_report.spec.default_filing_fee_inr
    )

    p_win = compute_win_probability(classification, rule_report, verification)
    expected_net = compute_expected_net_recovery(amount_inr, p_win, arb_fee, filing_fee)

    if p_win > 0.0:
        break_even = ((1.0 - p_win) * arb_fee + filing_fee) / p_win
    else:
        break_even = float("inf")

    if not verification.valid or classification == "tampered_evidence_rejected":
        action = ACTION_WRITE_OFF
        rationale = (
            f"Cryptographic verification failed ({verification.reason}). "
            "Rejecting representment to prevent submitting tampered evidence to the card network."
        )
    elif classification == "merchant_fulfillment_fault":
        action = ACTION_AUTO_REFUND
        rationale = (
            f"Merchant fulfillment or billing fault detected (P(win)={p_win:.1%}, "
            f"E[Net]=₹{expected_net:.2f}). Issue immediate pre-dispute auto-refund to avoid "
            f"₹{arb_fee:.0f} arbitration penalty."
        )
    elif expected_net > 0.0:
        action = ACTION_FIGHT
        rationale = (
            f"Positive expected net recovery E[Net]=₹{expected_net:.2f} "
            f"(P(win)={p_win:.1%}, Amount=₹{amount_inr:.2f} > Break-Even=₹{break_even:.2f}). "
            "Submit cryptographic representment brief."
        )
    else:
        action = ACTION_WRITE_OFF
        rationale = (
            f"Negative expected net recovery E[Net]=₹{expected_net:.2f} "
            f"(P(win)={p_win:.1%}, Amount=₹{amount_inr:.2f} <= Break-Even=₹{break_even:.2f}). "
            "Accept write-off to save representment and arbitration fees."
        )

    return EVOptimizationResult(
        win_probability=p_win,
        amount_inr=amount_inr,
        network_arbitration_fee_inr=arb_fee,
        representment_filing_fee_inr=filing_fee,
        expected_net_recovery_inr=expected_net,
        break_even_amount_inr=break_even if break_even != float("inf") else 999999999.0,
        recommended_action=action,
        rationale=rationale,
    )
