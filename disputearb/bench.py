"""
Synthetic Benchmark Suite (300 Disputes) for Chargeback Dispute Arbiter.

Evaluates 300 synthetic disputes across all 4 ground-truth categories:
  1. `first_party_friendly_fraud`
  2. `true_third_party_fraud`
  3. `merchant_fulfillment_fault`
  4. `tampered_evidence_rejected`

Compares 4 strategies:
  - `cryptographic_ev_arbiter`: Ed25519 + SHA-256 Merkle verification + Visa CE 3.0 + EV optimizer
  - `naive_fight_all`: Fights all 300 disputes unconditionally
  - `naive_amount_threshold_5000`: Fights iff disputed amount >= ₹5,000
  - `unverified_evidence`: Uses EV optimizer on raw JSON fields without verifying Ed25519/Merkle proofs

Caveat: the cases are generated to match the arbiter's own rules, and a fought dispute is scored
with the arbiter's own estimated P(win). The arbiter therefore wins this benchmark by construction;
the numbers show the bookkeeping works, not that it would recover more money on real disputes.
"""

from __future__ import annotations

import copy
import hashlib
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from disputearb.arbiter import (
    CLASS_FRIENDLY_FRAUD,
    CLASS_MERCHANT_FAULT,
    CLASS_TAMPERED_REJECTED,
    CLASS_TRUE_FRAUD,
    ArbitrationDecision,
    ChargebackArbiter,
    DisputeClaim,
)
from disputearb.optimizer import ACTION_FIGHT
from disputearb.receipts import (
    CheckoutAuthLeaf,
    DeliveryProofLeaf,
    EvidencePacket,
    MerchantSigner,
    PostPurchaseUsageLeaf,
    UsageEvent,
    VerificationResult,
    build_merkle_tree,
    compile_evidence_packet,
    hash_leaf,
)
from disputearb.rules import (
    SECONDS_PER_DAY,
    HistoricalTransaction,
    evaluate_reason_code_rules,
)
from disputearb.optimizer import optimize_representment_decision


@dataclass
class SyntheticDisputeCase:
    case_id: str
    ground_truth_category: str
    is_ce30_friendly_fraud: bool
    tamper_mode: str  # "none" or description of tampering
    claim: DisputeClaim
    packet: EvidencePacket
    historical_ledger: List[HistoricalTransaction]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "ground_truth_category": self.ground_truth_category,
            "is_ce30_friendly_fraud": self.is_ce30_friendly_fraud,
            "tamper_mode": self.tamper_mode,
            "claim": self.claim.to_dict(),
            "packet": self.packet.to_dict(),
            "historical_ledger": [h.to_dict() for h in self.historical_ledger],
        }


def _sha_short(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:24]


def generate_synthetic_disputes(
    num_cases: int = 300,
    seed: int = 20261014,
    signer: MerchantSigner | None = None,
) -> Tuple[List[SyntheticDisputeCase], MerchantSigner]:
    """
    Deterministically generate 300 synthetic disputes spanning all 4 categories
    and all 9 card-network / UPI reason codes. The case data depends only on `seed`;
    signatures use `signer`, or a fresh random key.
    """
    rng = random.Random(seed)
    signer = signer or MerchantSigner()
    base_ts = 1_725_000_000

    # Category counts for 300 cases (scaled proportionally if num_cases != 300)
    n_friendly = int(round(num_cases * 0.45))       # 135
    n_true_fraud = int(round(num_cases * 0.22))     # 66
    n_merchant_fault = int(round(num_cases * 0.18)) # 54
    n_tampered = num_cases - (n_friendly + n_true_fraud + n_merchant_fault)  # 45

    cases: List[SyntheticDisputeCase] = []
    idx = 0

    # 1. First-Party Friendly Fraud (135 cases)
    #    - 65 Visa 10.4 CE 3.0 qualified cases (some medium ₹1,800-₹4,800, some high ₹6,000-₹38,000, a few micro ₹180-₹240)
    #    - 70 across 13.1, 13.3, 13.6, 13.7, 4837, 4853, U10, U14 with strong 3DS2/OTP/usage proofs
    other_friendly_rcs = ["13.1", "13.3", "13.6", "13.7", "4837", "4853", "U10", "U14"]
    for i in range(n_friendly):
        idx += 1
        txn_id = f"TXN-FF-{idx:04d}"
        dispute_id = f"DSP-{idx:04d}"
        acct_id = f"ACCT-{1000 + idx}"
        dev_id = f"DEV-TRUSTED-{idx:04d}"
        ip_addr = f"49.36.{idx % 250}.{(idx * 7) % 250 + 1}"
        ship_hash = _sha_short(f"addr-bengaluru-{acct_id}")
        ts = base_ts + idx * 3600

        is_ce30 = i < 65
        if is_ce30:
            rc = "10.4"
        else:
            rc = other_friendly_rcs[(i - 65) % len(other_friendly_rcs)]

        # Vary amounts:
        #   - 10 micro-ticket cases (₹140 - ₹230) where fighting has E[Net] < 0
        #   - 55 mid-ticket cases (₹1,600 - ₹4,800) where E[Net] > 0 but Naive >= ₹5,000 misses them!
        #   - Remaining high-ticket cases (₹5,500 - ₹36,000)
        if i % 15 == 0:
            amount = round(rng.uniform(140.0, 220.0), 2)
        elif i % 2 == 1:
            amount = round(rng.uniform(1600.0, 4850.0), 2)
        else:
            amount = round(rng.uniform(5600.0, 34000.0), 2)

        auth = CheckoutAuthLeaf(
            txn_id=txn_id,
            account_id=acct_id,
            amount_inr=amount,
            three_ds_status="Y",
            eci="05",
            cavv=f"CAVV-{_sha_short(txn_id)[:16]}",
            device_id=dev_id,
            ip_address=ip_addr,
            avs_cvv_match=True,
            shipping_address_hash=ship_hash,
            timestamp=ts,
            credit_refund_processed=(rc == "13.6"),
            credit_arn=(f"ARN749283{idx:06d}" if rc == "13.6" else None),
            cancelled_before_billing=False,
        )
        delivery = DeliveryProofLeaf(
            delivered=True,
            carrier_signed_gps=f"12.{9100 + (idx % 800)},77.{5800 + (idx % 800)}",
            otp_verified_handoff=True,
            recipient_signature_hash=_sha_short(f"sig-{txn_id}"),
            delivery_timestamp=ts + 7200,
            as_described_qc_passed=True,
        )
        usage = PostPurchaseUsageLeaf(
            events=[
                UsageEvent(
                    event_type="app_session_active_use",
                    device_id=dev_id,
                    ip_address=ip_addr,
                    timestamp=ts + 14400,
                ),
                UsageEvent(
                    event_type="feature_consumption_verified",
                    device_id=dev_id,
                    ip_address=ip_addr,
                    timestamp=ts + 28800,
                ),
            ]
        )
        packet = compile_evidence_packet(auth, delivery, usage, signer=signer)

        ledger: List[HistoricalTransaction] = []
        if is_ce30 or rc in ("4837", "U10"):
            # Two undisputed prior transactions aged 150 and 240 days sharing >=3 core elements
            ledger.append(
                HistoricalTransaction(
                    txn_id=f"HIST-{idx:04d}-A",
                    account_id=acct_id,
                    ip_address=ip_addr,
                    device_id=dev_id,
                    shipping_address_hash=ship_hash,
                    amount_inr=round(amount * 0.85, 2),
                    timestamp=int(ts - 155 * SECONDS_PER_DAY),
                    disputed=False,
                    three_ds_status="Y",
                )
            )
            ledger.append(
                HistoricalTransaction(
                    txn_id=f"HIST-{idx:04d}-B",
                    account_id=acct_id,
                    ip_address=ip_addr,
                    device_id=dev_id,
                    shipping_address_hash=ship_hash,
                    amount_inr=round(amount * 1.10, 2),
                    timestamp=int(ts - 245 * SECONDS_PER_DAY),
                    disputed=False,
                    three_ds_status="Y",
                )
            )

        claim = DisputeClaim(
            dispute_id=dispute_id,
            txn_id=txn_id,
            reason_code=rc,
            amount_inr=amount,
            cardholder_statement=f"Customer disputes {rc} claiming unauthorized or unfulfilled charge.",
        )
        cases.append(
            SyntheticDisputeCase(
                case_id=dispute_id,
                ground_truth_category=CLASS_FRIENDLY_FRAUD,
                is_ce30_friendly_fraud=is_ce30,
                tamper_mode="none",
                claim=claim,
                packet=packet,
                historical_ledger=ledger,
            )
        )

    # 2. True Third-Party Fraud (66 cases)
    #    Unauthenticated (3DS=N, ECI=07), unrecognized foreign IP & device, no CE 3.0 history
    fraud_rcs = ["10.4", "4837", "U10"]
    for i in range(n_true_fraud):
        idx += 1
        txn_id = f"TXN-TF-{idx:04d}"
        dispute_id = f"DSP-{idx:04d}"
        acct_id = f"ACCT-{2000 + idx}"
        dev_id = f"DEV-ANON-BURNER-{idx:04d}"
        ip_addr = f"185.220.{idx % 250}.{(idx * 13) % 250 + 1}"
        ship_hash = _sha_short(f"drop-address-{idx}")
        ts = base_ts + idx * 3600
        rc = fraud_rcs[i % len(fraud_rcs)]

        # Mostly high amounts (>= ₹5,000) so naive threshold strategy fights and loses!
        if i % 4 == 0:
            amount = round(rng.uniform(1800.0, 4500.0), 2)
        else:
            amount = round(rng.uniform(5500.0, 28000.0), 2)

        auth = CheckoutAuthLeaf(
            txn_id=txn_id,
            account_id=acct_id,
            amount_inr=amount,
            three_ds_status="N",
            eci="07",
            cavv="",
            device_id=dev_id,
            ip_address=ip_addr,
            avs_cvv_match=False,
            shipping_address_hash=ship_hash,
            timestamp=ts,
        )
        delivery = DeliveryProofLeaf(
            delivered=False,
            carrier_signed_gps="",
            otp_verified_handoff=False,
            recipient_signature_hash="",
            delivery_timestamp=0,
        )
        usage = PostPurchaseUsageLeaf(events=[])
        packet = compile_evidence_packet(auth, delivery, usage, signer=signer)

        # Prior transaction has completely different device/IP/address (only 1 element: account_id)
        ledger = [
            HistoricalTransaction(
                txn_id=f"HIST-{idx:04d}-LEGIT",
                account_id=acct_id,
                ip_address="49.36.12.99",
                device_id=f"DEV-HOME-{acct_id}",
                shipping_address_hash=_sha_short(f"home-address-{acct_id}"),
                amount_inr=1500.0,
                timestamp=int(ts - 180 * SECONDS_PER_DAY),
                disputed=False,
            )
        ]

        claim = DisputeClaim(
            dispute_id=dispute_id,
            txn_id=txn_id,
            reason_code=rc,
            amount_inr=amount,
            cardholder_statement="Cardholder reports stolen credentials / unauthorized card-absent transaction.",
        )
        cases.append(
            SyntheticDisputeCase(
                case_id=dispute_id,
                ground_truth_category=CLASS_TRUE_FRAUD,
                is_ce30_friendly_fraud=False,
                tamper_mode="none",
                claim=claim,
                packet=packet,
                historical_ledger=ledger,
            )
        )

    # 3. Merchant Fulfillment Fault (54 cases)
    #    Undelivered merchandise (13.1, 4853, U14), failed QC (13.3), unissued refund (13.6),
    #    or billed after valid cancellation (13.7)
    fault_rcs = ["13.1", "13.3", "13.6", "13.7", "4853", "U14"]
    for i in range(n_merchant_fault):
        idx += 1
        txn_id = f"TXN-MF-{idx:04d}"
        dispute_id = f"DSP-{idx:04d}"
        acct_id = f"ACCT-{3000 + idx}"
        dev_id = f"DEV-CUST-{idx:04d}"
        ip_addr = f"106.51.{idx % 250}.{(idx * 11) % 250 + 1}"
        ship_hash = _sha_short(f"cust-addr-{acct_id}")
        ts = base_ts + idx * 3600
        rc = fault_rcs[i % len(fault_rcs)]
        amount = round(rng.uniform(2200.0, 22000.0), 2)

        delivered = rc in ("13.3", "13.7")
        qc_passed = rc != "13.3"
        cancelled_prior = rc == "13.7"

        auth = CheckoutAuthLeaf(
            txn_id=txn_id,
            account_id=acct_id,
            amount_inr=amount,
            three_ds_status="Y",
            eci="05",
            cavv=f"CAVV-{_sha_short(txn_id)[:16]}",
            device_id=dev_id,
            ip_address=ip_addr,
            avs_cvv_match=True,
            shipping_address_hash=ship_hash,
            timestamp=ts,
            credit_refund_processed=False,
            credit_arn=None,
            cancelled_before_billing=cancelled_prior,
        )
        delivery = DeliveryProofLeaf(
            delivered=delivered,
            carrier_signed_gps=("12.9716,77.5946" if delivered else ""),
            otp_verified_handoff=False,
            recipient_signature_hash=(_sha_short(f"sig-{txn_id}") if delivered else ""),
            delivery_timestamp=(ts + 3600 if delivered else 0),
            as_described_qc_passed=qc_passed,
        )
        usage = PostPurchaseUsageLeaf(events=[])
        packet = compile_evidence_packet(auth, delivery, usage, signer=signer)

        claim = DisputeClaim(
            dispute_id=dispute_id,
            txn_id=txn_id,
            reason_code=rc,
            amount_inr=amount,
            cardholder_statement=f"Customer reports valid merchant fulfillment / billing failure ({rc}).",
        )
        cases.append(
            SyntheticDisputeCase(
                case_id=dispute_id,
                ground_truth_category=CLASS_MERCHANT_FAULT,
                is_ce30_friendly_fraud=False,
                tamper_mode="none",
                claim=claim,
                packet=packet,
                historical_ledger=[],
            )
        )

    # 4. Tampered Evidence Rejected (45 cases)
    #    Originally unauthenticated / undelivered transactions where someone tampered with
    #    IP, device_id, 3DS status, delivery OTP, or recomputed Merkle hashes without Ed25519 key!
    tamper_modes = [
        "tamper_ip_address",
        "tamper_device_id",
        "tamper_3ds_status_and_eci",
        "tamper_delivery_otp_flag",
        "tamper_recomputed_merkle_forged_sig",
    ]
    for i in range(n_tampered):
        idx += 1
        txn_id = f"TXN-TMP-{idx:04d}"
        dispute_id = f"DSP-{idx:04d}"
        acct_id = f"ACCT-{4000 + idx}"
        legit_dev = f"DEV-LEGIT-{idx:04d}"
        legit_ip = f"49.37.{idx % 200}.{(idx * 5) % 200 + 1}"
        ship_hash = _sha_short(f"ship-{acct_id}")
        ts = base_ts + idx * 3600
        rc = "10.4" if i % 2 == 0 else "13.1"
        amount = round(rng.uniform(6200.0, 32000.0), 2)

        # Original signed receipt was weak (3DS=N, ECI=07, burner IP/device, OTP=False)
        orig_auth = CheckoutAuthLeaf(
            txn_id=txn_id,
            account_id=acct_id,
            amount_inr=amount,
            three_ds_status="N",
            eci="07",
            cavv="",
            device_id=f"DEV-FOREIGN-{idx:04d}",
            ip_address="198.51.100.42",
            avs_cvv_match=False,
            shipping_address_hash=ship_hash,
            timestamp=ts,
        )
        orig_delivery = DeliveryProofLeaf(
            delivered=False,
            carrier_signed_gps="",
            otp_verified_handoff=False,
            recipient_signature_hash="",
            delivery_timestamp=0,
        )
        orig_usage = PostPurchaseUsageLeaf(events=[])
        packet = compile_evidence_packet(orig_auth, orig_delivery, orig_usage, signer=signer)

        # Now apply post-signing tampering so it looks like strong friendly-fraud evidence
        # if cryptographic signatures / Merkle trees are ignored!
        mode = tamper_modes[i % len(tamper_modes)]
        tampered_packet = copy.deepcopy(packet)
        tampered_packet.checkout_auth.ip_address = legit_ip
        tampered_packet.checkout_auth.device_id = legit_dev
        tampered_packet.checkout_auth.three_ds_status = "Y"
        tampered_packet.checkout_auth.eci = "05"
        tampered_packet.checkout_auth.cavv = f"FORGED-CAVV-{idx}"
        tampered_packet.delivery_proof.delivered = True
        tampered_packet.delivery_proof.otp_verified_handoff = True
        tampered_packet.delivery_proof.carrier_signed_gps = "12.9716,77.5946"
        tampered_packet.delivery_proof.recipient_signature_hash = _sha_short(f"forged-sig-{idx}")
        tampered_packet.delivery_proof.delivery_timestamp = ts + 3600
        tampered_packet.post_purchase_usage.events = [
            UsageEvent(
                event_type="forged_session_login",
                device_id=legit_dev,
                ip_address=legit_ip,
                timestamp=ts + 7200,
            )
        ]

        if mode == "tamper_recomputed_merkle_forged_sig":
            # Attacker even recomputes leaf hashes and Merkle root, but lacks MerchantSigner private key
            new_leaves = {
                "checkout_auth": hash_leaf("checkout_auth", tampered_packet.checkout_auth.to_dict()),
                "delivery_proof": hash_leaf("delivery_proof", tampered_packet.delivery_proof.to_dict()),
                "post_purchase_usage": hash_leaf(
                    "post_purchase_usage", tampered_packet.post_purchase_usage.to_dict()
                ),
            }
            new_root, new_proofs = build_merkle_tree(new_leaves)
            tampered_packet.leaf_hashes = new_leaves
            tampered_packet.merkle_root = new_root
            tampered_packet.inclusion_proofs = new_proofs

        ledger = [
            HistoricalTransaction(
                txn_id=f"HIST-TMP-{idx:04d}-1",
                account_id=acct_id,
                ip_address=legit_ip,
                device_id=legit_dev,
                shipping_address_hash=ship_hash,
                amount_inr=4500.0,
                timestamp=int(ts - 160 * SECONDS_PER_DAY),
                disputed=False,
            ),
            HistoricalTransaction(
                txn_id=f"HIST-TMP-{idx:04d}-2",
                account_id=acct_id,
                ip_address=legit_ip,
                device_id=legit_dev,
                shipping_address_hash=ship_hash,
                amount_inr=5200.0,
                timestamp=int(ts - 230 * SECONDS_PER_DAY),
                disputed=False,
            ),
        ]

        claim = DisputeClaim(
            dispute_id=dispute_id,
            txn_id=txn_id,
            reason_code=rc,
            amount_inr=amount,
            cardholder_statement="Cardholder disputes transaction; submitted evidence packet was altered post-signing.",
        )
        cases.append(
            SyntheticDisputeCase(
                case_id=dispute_id,
                ground_truth_category=CLASS_TAMPERED_REJECTED,
                is_ce30_friendly_fraud=False,
                tamper_mode=mode,
                claim=claim,
                packet=tampered_packet,
                historical_ledger=ledger,
            )
        )

    return cases, signer


def _ground_truth_fight_payoff(case: SyntheticDisputeCase, decision: ArbitrationDecision) -> float:
    """
    Compute the expected net ₹ recovery when a strategy chooses to FIGHT_REPRESENTMENT
    on `case`:
      - For valid `first_party_friendly_fraud`: card network accepts the valid cryptographic
        evidence with the arbiter's estimated win probability P(win), yielding:
            P(win) * Amount - (1 - P(win)) * ArbFee - FilingFee
      - For `true_third_party_fraud` or `merchant_fulfillment_fault`: fighting with weak/faulty
        evidence has the low estimated P(win) (4%-6%), losing arbitration + filing fees almost always.
      - For `tampered_evidence_rejected`: card network / issuer forensic audit rejects forged
        receipts with 0% win probability AND assesses full arbitration + filing fees
        plus a network compliance penalty (₹1,500) for altered representment records.
    """
    arb_fee = decision.ev_optimization.network_arbitration_fee_inr
    filing_fee = decision.ev_optimization.representment_filing_fee_inr
    amount = case.claim.amount_inr

    if case.ground_truth_category == CLASS_TAMPERED_REJECTED:
        # 0% win rate + arbitration fee + filing fee + ₹1,500 forged-representment compliance penalty
        return -(arb_fee + filing_fee + 1500.0)

    p_win = decision.ev_optimization.win_probability
    return p_win * amount - (1.0 - p_win) * arb_fee - filing_fee


@dataclass
class StrategyBenchmarkMetrics:
    strategy_name: str
    disputes_evaluated: int
    disputes_fought: int
    disputes_written_off: int
    disputes_auto_refunded: int
    total_net_recovery_inr: float
    avg_net_recovery_per_dispute_inr: float
    forged_packets_submitted: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_name": self.strategy_name,
            "disputes_evaluated": self.disputes_evaluated,
            "disputes_fought": self.disputes_fought,
            "disputes_written_off": self.disputes_written_off,
            "disputes_auto_refunded": self.disputes_auto_refunded,
            "total_net_recovery_inr": round(self.total_net_recovery_inr, 2),
            "avg_net_recovery_per_dispute_inr": round(self.avg_net_recovery_per_dispute_inr, 2),
            "forged_packets_submitted": self.forged_packets_submitted,
        }


def run_benchmark(num_cases: int = 300, seed: int = 20261014) -> Dict[str, Any]:
    """
    Run the 300-dispute benchmark comparing:
      1. `cryptographic_ev_arbiter` (Ours)
      2. `naive_fight_all`
      3. `naive_amount_threshold_5000`
      4. `unverified_evidence`
    """
    cases, signer = generate_synthetic_disputes(num_cases=num_cases, seed=seed)
    arbiter = ChargebackArbiter(trusted_public_key_hex=signer.public_key_hex)

    tampered_total = 0
    tampered_detected = 0
    ce30_total = 0
    ce30_caught = 0
    category_counts: Dict[str, int] = {
        CLASS_FRIENDLY_FRAUD: 0,
        CLASS_TRUE_FRAUD: 0,
        CLASS_MERCHANT_FAULT: 0,
        CLASS_TAMPERED_REJECTED: 0,
    }
    classification_correct = 0

    # Strategy accumulators
    strat_stats: Dict[str, Dict[str, float]] = {
        "cryptographic_ev_arbiter": {
            "fought": 0,
            "write_off": 0,
            "auto_refund": 0,
            "net_inr": 0.0,
            "forged_submitted": 0,
        },
        "naive_fight_all": {
            "fought": 0,
            "write_off": 0,
            "auto_refund": 0,
            "net_inr": 0.0,
            "forged_submitted": 0,
        },
        "naive_amount_threshold_5000": {
            "fought": 0,
            "write_off": 0,
            "auto_refund": 0,
            "net_inr": 0.0,
            "forged_submitted": 0,
        },
        "unverified_evidence": {
            "fought": 0,
            "write_off": 0,
            "auto_refund": 0,
            "net_inr": 0.0,
            "forged_submitted": 0,
        },
    }

    for case in cases:
        category_counts[case.ground_truth_category] = (
            category_counts.get(case.ground_truth_category, 0) + 1
        )
        decision = arbiter.evaluate_dispute(
            case.claim, case.packet, historical_ledger=case.historical_ledger
        )

        if decision.classification == case.ground_truth_category:
            classification_correct += 1

        if case.ground_truth_category == CLASS_TAMPERED_REJECTED:
            tampered_total += 1
            if (not decision.verification.valid) and (
                decision.classification == CLASS_TAMPERED_REJECTED
            ):
                tampered_detected += 1

        if case.is_ce30_friendly_fraud:
            ce30_total += 1
            if (
                decision.rule_report.ce30.qualified
                and decision.classification == CLASS_FRIENDLY_FRAUD
            ):
                ce30_caught += 1

        fight_payoff = _ground_truth_fight_payoff(case, decision)
        is_forged = case.ground_truth_category == CLASS_TAMPERED_REJECTED

        # 1. Cryptographic EV Arbiter (Ours)
        act = decision.recommended_action
        if act == ACTION_FIGHT:
            strat_stats["cryptographic_ev_arbiter"]["fought"] += 1
            strat_stats["cryptographic_ev_arbiter"]["net_inr"] += fight_payoff
            if is_forged:
                strat_stats["cryptographic_ev_arbiter"]["forged_submitted"] += 1
        elif act == "AUTO_REFUND_PRE_DISPUTE":
            strat_stats["cryptographic_ev_arbiter"]["auto_refund"] += 1
            # Assumed: a pre-dispute refund saves a ₹150 network dispute fee (illustrative figure)
            strat_stats["cryptographic_ev_arbiter"]["net_inr"] += 150.0
        else:
            strat_stats["cryptographic_ev_arbiter"]["write_off"] += 1

        # 2. Naive Fight-All
        strat_stats["naive_fight_all"]["fought"] += 1
        strat_stats["naive_fight_all"]["net_inr"] += fight_payoff
        if is_forged:
            strat_stats["naive_fight_all"]["forged_submitted"] += 1

        # 3. Naive Amount-Threshold (fight if amount >= ₹5,000)
        if case.claim.amount_inr >= 5000.0:
            strat_stats["naive_amount_threshold_5000"]["fought"] += 1
            strat_stats["naive_amount_threshold_5000"]["net_inr"] += fight_payoff
            if is_forged:
                strat_stats["naive_amount_threshold_5000"]["forged_submitted"] += 1
        else:
            strat_stats["naive_amount_threshold_5000"]["write_off"] += 1

        # 4. Unverified Evidence Baseline (skips Ed25519/Merkle check)
        fake_valid = VerificationResult(
            valid=True,
            merkle_valid=True,
            signature_valid=True,
            inclusion_proofs_valid=True,
            tampered_leaves=[],
            computed_merkle_root=case.packet.merkle_root,
            claimed_merkle_root=case.packet.merkle_root,
            reason="Unverified mode (cryptographic checks bypassed).",
        )
        unverified_rule = evaluate_reason_code_rules(
            case.claim.reason_code, case.packet, historical_ledger=case.historical_ledger
        )
        unverified_class = (
            CLASS_FRIENDLY_FRAUD
            if is_forged
            else decision.classification
        )
        unverified_ev = optimize_representment_decision(
            classification=unverified_class,
            amount_inr=case.claim.amount_inr,
            rule_report=unverified_rule,
            verification=fake_valid,
        )
        if unverified_ev.recommended_action == ACTION_FIGHT:
            strat_stats["unverified_evidence"]["fought"] += 1
            strat_stats["unverified_evidence"]["net_inr"] += fight_payoff
            if is_forged:
                strat_stats["unverified_evidence"]["forged_submitted"] += 1
        elif unverified_ev.recommended_action == "AUTO_REFUND_PRE_DISPUTE":
            strat_stats["unverified_evidence"]["auto_refund"] += 1
            strat_stats["unverified_evidence"]["net_inr"] += 150.0
        else:
            strat_stats["unverified_evidence"]["write_off"] += 1

    strategies_out: Dict[str, Dict[str, Any]] = {}
    for s_name, st in strat_stats.items():
        m = StrategyBenchmarkMetrics(
            strategy_name=s_name,
            disputes_evaluated=num_cases,
            disputes_fought=int(st["fought"]),
            disputes_written_off=int(st["write_off"]),
            disputes_auto_refunded=int(st["auto_refund"]),
            total_net_recovery_inr=st["net_inr"],
            avg_net_recovery_per_dispute_inr=st["net_inr"] / max(1, num_cases),
            forged_packets_submitted=int(st["forged_submitted"]),
        )
        strategies_out[s_name] = m.to_dict()

    tamper_rate = tampered_detected / max(1, tampered_total)
    ce30_rate = ce30_caught / max(1, ce30_total)
    accuracy = classification_correct / max(1, num_cases)

    ours_net = strategies_out["cryptographic_ev_arbiter"]["total_net_recovery_inr"]
    fight_all_net = strategies_out["naive_fight_all"]["total_net_recovery_inr"]
    threshold_net = strategies_out["naive_amount_threshold_5000"]["total_net_recovery_inr"]
    unverified_net = strategies_out["unverified_evidence"]["total_net_recovery_inr"]

    return {
        "total_disputes": num_cases,
        "seed": seed,
        "category_distribution": category_counts,
        "tamper_detection_rate": round(tamper_rate, 4),
        "tampered_detected": tampered_detected,
        "tampered_total": tampered_total,
        "ce30_friendly_fraud_catch_rate": round(ce30_rate, 4),
        "ce30_caught": ce30_caught,
        "ce30_total": ce30_total,
        "classification_accuracy": round(accuracy, 4),
        "strategies": strategies_out,
        "net_recovery_uplift_inr": {
            "vs_naive_fight_all": round(ours_net - fight_all_net, 2),
            "vs_naive_amount_threshold_5000": round(ours_net - threshold_net, 2),
            "vs_unverified_evidence": round(ours_net - unverified_net, 2),
        },
    }
