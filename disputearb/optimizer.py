"""
Expected-Value (EV) Representment Optimizer.

Estimates representment win probability P(win | evidence, reason_code) from hand-set rule
weights (no outcome data was used to calibrate them) and Expected Net Recovery:
    E[Net] = P(win) * Amount - (1 - P(win)) * NetworkArbitrationFee - RepresentmentFilingFee

Money is Decimal throughout (rupees, to the paisa); only the win probability is a float.

Recommends one of:
  - FIGHT_REPRESENTMENT
  - ACCEPT_WRITE_OFF
  - AUTO_REFUND_PRE_DISPUTE
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Optional

from disputearb.receipts import PAISE, VerificationResult, as_amount
from disputearb.rules import RuleEvaluationReport

ACTION_FIGHT = "FIGHT_REPRESENTMENT"
ACTION_WRITE_OFF = "ACCEPT_WRITE_OFF"
ACTION_AUTO_REFUND = "AUTO_REFUND_PRE_DISPUTE"


@dataclass
class EVOptimizationResult:
    win_probability: float
    amount_inr: Decimal
    network_arbitration_fee_inr: Decimal
    representment_filing_fee_inr: Decimal
    expected_net_recovery_inr: Decimal
    break_even_amount_inr: Decimal
    recommended_action: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "win_probability": round(self.win_probability, 4),
            "amount_inr": self.amount_inr.quantize(PAISE).to_eng_string(),
            "network_arbitration_fee_inr": self.network_arbitration_fee_inr.quantize(PAISE).to_eng_string(),
            "representment_filing_fee_inr": self.representment_filing_fee_inr.quantize(PAISE).to_eng_string(),
            "expected_net_recovery_inr": self.expected_net_recovery_inr.quantize(PAISE).to_eng_string(),
            "break_even_amount_inr": self.break_even_amount_inr.quantize(PAISE).to_eng_string(),
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
        }


def compute_expected_net_recovery(
    amount_inr: Decimal,
    win_probability: float,
    network_arbitration_fee_inr: Decimal,
    representment_filing_fee_inr: Decimal,
) -> Decimal:
    """
    Compute Expected Net Recovery (INR), unrounded:
        E[Net] = P(win) * Amount - (1 - P(win)) * NetworkArbitrationFee - RepresentmentFilingFee
    """
    p = Decimal(str(max(0.0, min(1.0, float(win_probability)))))
    return (
        p * as_amount(amount_inr)
        - (1 - p) * as_amount(network_arbitration_fee_inr)
        - as_amount(representment_filing_fee_inr)
    )


def compute_win_probability(
    classification: str,
    rule_report: RuleEvaluationReport,
    verification: VerificationResult,
) -> float:
    """
    Estimate representment win probability P(win | evidence, reason_code) from fixed weights.
    The weights are judgement calls, not fitted to dispute outcomes; replace them with
    win rates measured on your own representment history before trusting the EV numbers.
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
    amount_inr: Decimal,
    rule_report: RuleEvaluationReport,
    verification: VerificationResult,
    network_arbitration_fee_inr: Optional[Decimal] = None,
    representment_filing_fee_inr: Optional[Decimal] = None,
) -> EVOptimizationResult:
    """
    Compute estimated win probability, expected net recovery in INR, break-even threshold,
    and optimal decision (`FIGHT_REPRESENTMENT`, `ACCEPT_WRITE_OFF`, or `AUTO_REFUND_PRE_DISPUTE`).
    """
    amount_inr = as_amount(amount_inr)
    arb_fee = as_amount(
        network_arbitration_fee_inr
        if network_arbitration_fee_inr is not None
        else rule_report.spec.default_arbitration_fee_inr
    )
    filing_fee = as_amount(
        representment_filing_fee_inr
        if representment_filing_fee_inr is not None
        else rule_report.spec.default_filing_fee_inr
    )

    p_win = compute_win_probability(classification, rule_report, verification)
    expected_net = compute_expected_net_recovery(amount_inr, p_win, arb_fee, filing_fee)

    p = Decimal(str(p_win))
    break_even = ((1 - p) * arb_fee + filing_fee) / p if p > 0 else None

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
    elif expected_net > 0:
        action = ACTION_FIGHT
        rationale = (
            f"Positive expected net recovery E[Net]=₹{expected_net:.2f} "
            f"(P(win)={p_win:.1%}, Amount=₹{amount_inr:.2f} > Break-Even=₹{break_even or 0:.2f}). "
            "Submit cryptographic representment brief."
        )
    else:
        action = ACTION_WRITE_OFF
        rationale = (
            f"Negative expected net recovery E[Net]=₹{expected_net:.2f} "
            f"(P(win)={p_win:.1%}, Amount=₹{amount_inr:.2f} <= Break-Even=₹{'inf' if break_even is None else f'{break_even:.2f}'}). "
            "Accept write-off to save representment and arbitration fees."
        )

    return EVOptimizationResult(
        win_probability=p_win,
        amount_inr=amount_inr,
        network_arbitration_fee_inr=arb_fee,
        representment_filing_fee_inr=filing_fee,
        expected_net_recovery_inr=expected_net,
        break_even_amount_inr=break_even if break_even is not None else Decimal("999999999"),
        recommended_action=action,
        rationale=rationale,
    )
