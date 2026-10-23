"""
Card-Network & RuPay/UPI Dispute Reason-Code Rules and Visa Compelling Evidence 3.0 (CE 3.0) Engine.

Supported Reason Codes:
  - Visa 10.4: Other Fraud — Card-Absent Environment (with Visa CE 3.0 qualification)
  - Visa 13.1: Merchandise / Services Not Received
  - Visa 13.3: Not as Described or Defective Merchandise
  - Visa 13.6: Credit Not Processed
  - Visa 13.7: Cancelled Merchandise / Services (Recurring)
  - Mastercard 4837: No Cardholder Authorization
  - Mastercard 4853: Cardholder Dispute
  - RuPay / UPI U10: Unauthorised UPI Debit
  - RuPay / UPI U14: Goods / Services Not Provided
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from disputearb.receipts import EvidencePacket

SECONDS_PER_DAY = 86400.0
CE30_MIN_AGE_DAYS = 120.0
CE30_MAX_AGE_DAYS = 365.0
CE30_CORE_ELEMENTS = ("ip_address", "device_id", "shipping_address_hash", "account_id")


@dataclass
class ReasonCodeSpec:
    code: str
    network: str
    category: str  # "FRAUD" or "CONSUMER_DISPUTE"
    title: str
    description: str
    default_arbitration_fee_inr: float
    default_filing_fee_inr: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


REASON_CODE_CATALOG: Dict[str, ReasonCodeSpec] = {
    "10.4": ReasonCodeSpec(
        code="10.4",
        network="VISA",
        category="FRAUD",
        title="Other Fraud — Card-Absent Environment",
        description=(
            "Cardholder claims they did not authorize or participate in a card-absent transaction. "
            "Remediable via Visa Compelling Evidence 3.0 (CE 3.0) or 3DS2 ECI 05 liability shift."
        ),
        default_arbitration_fee_inr=1200.0,
        default_filing_fee_inr=250.0,
    ),
    "13.1": ReasonCodeSpec(
        code="13.1",
        network="VISA",
        category="CONSUMER_DISPUTE",
        title="Merchandise / Services Not Received",
        description=(
            "Cardholder claims paid goods or services were never delivered by the agreed date. "
            "Requires carrier-signed GPS + OTP-verified handoff receipt."
        ),
        default_arbitration_fee_inr=1200.0,
        default_filing_fee_inr=250.0,
    ),
    "13.3": ReasonCodeSpec(
        code="13.3",
        network="VISA",
        category="CONSUMER_DISPUTE",
        title="Not as Described or Defective Merchandise",
        description=(
            "Cardholder claims delivered merchandise was materially different or defective. "
            "Requires QC inspection hash, delivery signature, and post-delivery usage telemetry."
        ),
        default_arbitration_fee_inr=1200.0,
        default_filing_fee_inr=250.0,
    ),
    "13.6": ReasonCodeSpec(
        code="13.6",
        network="VISA",
        category="CONSUMER_DISPUTE",
        title="Credit Not Processed",
        description=(
            "Cardholder claims merchant agreed to a refund/credit but never processed it, "
            "or claims duplicate debit when credit ARN already settled."
        ),
        default_arbitration_fee_inr=1200.0,
        default_filing_fee_inr=250.0,
    ),
    "13.7": ReasonCodeSpec(
        code="13.7",
        network="VISA",
        category="CONSUMER_DISPUTE",
        title="Cancelled Merchandise / Services (Recurring)",
        description=(
            "Cardholder claims subscription was cancelled prior to billing. "
            "Rebutted by post-billing authenticated app sessions and lack of prior cancellation."
        ),
        default_arbitration_fee_inr=1200.0,
        default_filing_fee_inr=250.0,
    ),
    "4837": ReasonCodeSpec(
        code="4837",
        network="MASTERCARD",
        category="FRAUD",
        title="No Cardholder Authorization",
        description=(
            "Mastercard card-not-present fraud claim. Rebutted by 3DS2 ECI 05/02 CAVV "
            "authentication, historical device/IP footprint, and OTP-verified delivery."
        ),
        default_arbitration_fee_inr=1250.0,
        default_filing_fee_inr=250.0,
    ),
    "4853": ReasonCodeSpec(
        code="4853",
        network="MASTERCARD",
        category="CONSUMER_DISPUTE",
        title="Cardholder Dispute — Goods/Services Not Provided or Defective",
        description=(
            "Mastercard consumer dispute over non-delivery or quality. "
            "Rebutted by signed GPS/OTP delivery proof and post-purchase usage logs."
        ),
        default_arbitration_fee_inr=1250.0,
        default_filing_fee_inr=250.0,
    ),
    "U10": ReasonCodeSpec(
        code="U10",
        network="RUPAY_UPI",
        category="FRAUD",
        title="Unauthorised UPI Debit",
        description=(
            "NPCI UPI dispute claiming unauthorized debit. Rebutted by device-bound MPIN/3DS "
            "authentication, historical device_id/IP continuity, and post-purchase app sessions."
        ),
        default_arbitration_fee_inr=600.0,
        default_filing_fee_inr=120.0,
    ),
    "U14": ReasonCodeSpec(
        code="U14",
        network="RUPAY_UPI",
        category="CONSUMER_DISPUTE",
        title="Goods / Services Not Provided (UPI)",
        description=(
            "NPCI UPI dispute where customer claims merchant did not fulfill goods/services "
            "after UPI debit. Rebutted by OTP-verified delivery proof and usage events."
        ),
        default_arbitration_fee_inr=600.0,
        default_filing_fee_inr=120.0,
    ),
}


@dataclass
class HistoricalTransaction:
    txn_id: str
    account_id: str
    ip_address: str
    device_id: str
    shipping_address_hash: str
    amount_inr: float
    timestamp: int
    disputed: bool = False
    three_ds_status: str = "Y"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HistoricalTransaction":
        return cls(
            txn_id=str(data["txn_id"]),
            account_id=str(data["account_id"]),
            ip_address=str(data["ip_address"]),
            device_id=str(data["device_id"]),
            shipping_address_hash=str(data["shipping_address_hash"]),
            amount_inr=float(data.get("amount_inr", 0.0)),
            timestamp=int(data["timestamp"]),
            disputed=bool(data.get("disputed", False)),
            three_ds_status=str(data.get("three_ds_status", "Y")),
        )


@dataclass
class CE30MatchDetail:
    txn_id: str
    age_days: float
    matched_elements: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "age_days": round(self.age_days, 2),
            "matched_elements": list(self.matched_elements),
        }


@dataclass
class CE30QualificationResult:
    qualified: bool
    qualifying_txn_ids: List[str] = field(default_factory=list)
    matches: List[CE30MatchDetail] = field(default_factory=list)
    shared_elements_union: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qualified": self.qualified,
            "qualifying_txn_ids": list(self.qualifying_txn_ids),
            "matches": [m.to_dict() for m in self.matches],
            "shared_elements_union": list(self.shared_elements_union),
            "summary": self.summary,
        }


def evaluate_visa_ce30(
    packet: EvidencePacket,
    historical_ledger: List[HistoricalTransaction],
) -> CE30QualificationResult:
    """
    Evaluate Visa Compelling Evidence 3.0 (CE 3.0) footprint:
    Checks whether the customer has >= 2 prior undisputed transactions aged 120-365 days
    before the disputed transaction that share >= 2 core elements
    (`ip_address`, `device_id`, `shipping_address_hash`, `account_id`)
    with the disputed transaction.
    """
    auth = packet.checkout_auth
    disputed_ts = auth.timestamp
    disputed_elements = {
        "ip_address": auth.ip_address,
        "device_id": auth.device_id,
        "shipping_address_hash": auth.shipping_address_hash,
        "account_id": auth.account_id,
    }

    qualifying_matches: List[CE30MatchDetail] = []
    shared_union = set()

    for prior in historical_ledger:
        if prior.txn_id == packet.txn_id:
            continue
        if prior.disputed:
            continue
        age_days = (disputed_ts - prior.timestamp) / SECONDS_PER_DAY
        if not (CE30_MIN_AGE_DAYS <= age_days <= CE30_MAX_AGE_DAYS):
            continue

        prior_elements = {
            "ip_address": prior.ip_address,
            "device_id": prior.device_id,
            "shipping_address_hash": prior.shipping_address_hash,
            "account_id": prior.account_id,
        }
        matched: List[str] = []
        for elem_name in CE30_CORE_ELEMENTS:
            val_now = disputed_elements.get(elem_name, "")
            val_prev = prior_elements.get(elem_name, "")
            if val_now and val_prev and val_now == val_prev:
                matched.append(elem_name)

        if len(matched) >= 2:
            qualifying_matches.append(
                CE30MatchDetail(
                    txn_id=prior.txn_id,
                    age_days=age_days,
                    matched_elements=matched,
                )
            )
            shared_union.update(matched)

    qualified = len(qualifying_matches) >= 2
    qualifying_ids = [m.txn_id for m in qualifying_matches]
    sorted_union = [e for e in CE30_CORE_ELEMENTS if e in shared_union]

    if qualified:
        summary = (
            f"Visa CE 3.0 QUALIFIED: {len(qualifying_matches)} undisputed historical "
            f"transactions ({', '.join(qualifying_ids[:4])}) aged 120-365 days match "
            f">=2 core elements ({', '.join(sorted_union)})."
        )
    else:
        summary = (
            f"Visa CE 3.0 NOT QUALIFIED: found {len(qualifying_matches)} qualifying prior "
            "transactions (minimum 2 required aged 120-365 days with >=2 shared core elements)."
        )

    return CE30QualificationResult(
        qualified=qualified,
        qualifying_txn_ids=qualifying_ids,
        matches=qualifying_matches,
        shared_elements_union=sorted_union,
        summary=summary,
    )


@dataclass
class RuleEvaluationReport:
    reason_code: str
    spec: ReasonCodeSpec
    ce30: CE30QualificationResult
    three_ds_authenticated: bool
    liability_shift_eci05: bool
    otp_delivery_verified: bool
    gps_and_signature_present: bool
    post_purchase_same_device_or_ip_count: int
    matching_usage_events: List[Dict[str, Any]]
    rule_findings: List[str]
    evidence_strength_score: float  # [0.0, 1.0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "spec": self.spec.to_dict(),
            "ce30": self.ce30.to_dict(),
            "three_ds_authenticated": self.three_ds_authenticated,
            "liability_shift_eci05": self.liability_shift_eci05,
            "otp_delivery_verified": self.otp_delivery_verified,
            "gps_and_signature_present": self.gps_and_signature_present,
            "post_purchase_same_device_or_ip_count": self.post_purchase_same_device_or_ip_count,
            "matching_usage_events": self.matching_usage_events,
            "rule_findings": list(self.rule_findings),
            "evidence_strength_score": round(self.evidence_strength_score, 4),
        }


def evaluate_reason_code_rules(
    reason_code: str,
    packet: EvidencePacket,
    historical_ledger: Optional[List[HistoricalTransaction]] = None,
) -> RuleEvaluationReport:
    """Evaluate card-network / RuPay-UPI reason code rules against an EvidencePacket."""
    if historical_ledger is None:
        historical_ledger = []

    spec = REASON_CODE_CATALOG.get(
        reason_code,
        ReasonCodeSpec(
            code=reason_code,
            network="UNKNOWN",
            category="FRAUD",
            title=f"Dispute Reason Code {reason_code}",
            description="Generic network dispute reason code.",
            default_arbitration_fee_inr=1200.0,
            default_filing_fee_inr=250.0,
        ),
    )

    auth = packet.checkout_auth
    delivery = packet.delivery_proof
    usage = packet.post_purchase_usage

    ce30 = evaluate_visa_ce30(packet, historical_ledger)
    three_ds_authenticated = auth.three_ds_status.upper() == "Y" and auth.eci in ("05", "06")
    liability_shift_eci05 = (
        auth.three_ds_status.upper() == "Y"
        and auth.eci == "05"
        and bool(auth.cavv.strip())
    )
    otp_delivery_verified = bool(delivery.delivered and delivery.otp_verified_handoff)
    gps_and_signature_present = bool(
        delivery.delivered
        and delivery.carrier_signed_gps.strip()
        and delivery.recipient_signature_hash.strip()
        and delivery.delivery_timestamp >= auth.timestamp
    )

    matching_usage_events: List[Dict[str, Any]] = []
    for ev in usage.events:
        if ev.timestamp >= auth.timestamp and (
            ev.device_id == auth.device_id or ev.ip_address == auth.ip_address
        ):
            matching_usage_events.append(ev.to_dict())

    post_usage_count = len(matching_usage_events)
    findings: List[str] = []

    if ce30.qualified:
        findings.append(ce30.summary)
    if liability_shift_eci05:
        findings.append(
            f"3DS2 Full Authentication (status=Y, ECI=05, CAVV={auth.cavv[:10]}...) establishes issuer liability shift."
        )
    elif three_ds_authenticated:
        findings.append(f"3DS2 Attempted/Partial Authentication (status={auth.three_ds_status}, ECI={auth.eci}).")
    else:
        findings.append(f"No 3DS2 Authentication (status={auth.three_ds_status}, ECI={auth.eci}).")

    if otp_delivery_verified and gps_and_signature_present:
        findings.append(
            f"Fulfillment verified: carrier GPS ({delivery.carrier_signed_gps}), "
            f"OTP handoff=True, signature_hash={delivery.recipient_signature_hash[:12]}..."
        )
    elif not delivery.delivered:
        findings.append("Fulfillment fault: merchandise not marked delivered.")
    else:
        findings.append("Fulfillment partial: delivered without complete OTP/GPS cryptographic handoff.")

    if post_usage_count > 0:
        findings.append(
            f"Post-purchase engagement: {post_usage_count} authenticated session/usage event(s) "
            f"from matching device_id ({auth.device_id}) or IP ({auth.ip_address})."
        )

    # Compute reason-code-specific evidence strength in [0.0, 1.0]
    score = 0.0
    if reason_code in ("10.4", "4837", "U10"):
        # Fraud / Unauthorized claims
        if ce30.qualified:
            score += 0.55
        if liability_shift_eci05:
            score += 0.45
        elif three_ds_authenticated:
            score += 0.20
        if auth.avs_cvv_match:
            score += 0.10
        if otp_delivery_verified and gps_and_signature_present:
            score += 0.25
        if post_usage_count >= 1:
            score += 0.20
    elif reason_code in ("13.1", "4853", "U14"):
        # Merchandise / Services Not Received
        if otp_delivery_verified and gps_and_signature_present:
            score += 0.65
        elif delivery.delivered and gps_and_signature_present:
            score += 0.35
        if post_usage_count >= 1:
            score += 0.25
        if liability_shift_eci05 or ce30.qualified:
            score += 0.15
    elif reason_code == "13.3":
        # Not as Described
        if delivery.delivered and delivery.as_described_qc_passed and gps_and_signature_present:
            score += 0.55
            findings.append("Pre-shipment QC hash and intact recipient handoff verified.")
        elif not delivery.as_described_qc_passed:
            findings.append("Merchant QC flag indicates item defect or mismatch.")
        if otp_delivery_verified:
            score += 0.20
        if post_usage_count >= 2:
            score += 0.25
        elif post_usage_count == 1:
            score += 0.15
    elif reason_code == "13.6":
        # Credit Not Processed
        if auth.credit_refund_processed and auth.credit_arn:
            score += 0.85
            findings.append(f"Prior credit/refund already processed under ARN {auth.credit_arn}.")
        elif otp_delivery_verified and not auth.cancelled_before_billing:
            score += 0.70
            findings.append("No refund owed: order fulfilled with OTP handoff and active usage.")
        else:
            findings.append("Refund was due or unfulfilled without credit ARN on file.")
    elif reason_code == "13.7":
        # Cancelled Recurring
        if not auth.cancelled_before_billing and post_usage_count >= 1:
            score += 0.85
            findings.append(
                "No cancellation prior to billing timestamp, and customer actively used subscription post-billing."
            )
        elif auth.cancelled_before_billing:
            findings.append("Merchant logs confirm cancellation request occurred before billing timestamp.")
        else:
            score += 0.35
    else:
        if ce30.qualified:
            score += 0.50
        if liability_shift_eci05:
            score += 0.35
        if otp_delivery_verified:
            score += 0.25

    score = min(1.0, max(0.0, score))

    return RuleEvaluationReport(
        reason_code=reason_code,
        spec=spec,
        ce30=ce30,
        three_ds_authenticated=three_ds_authenticated,
        liability_shift_eci05=liability_shift_eci05,
        otp_delivery_verified=otp_delivery_verified,
        gps_and_signature_present=gps_and_signature_present,
        post_purchase_same_device_or_ip_count=post_usage_count,
        matching_usage_events=matching_usage_events,
        rule_findings=findings,
        evidence_strength_score=score,
    )
