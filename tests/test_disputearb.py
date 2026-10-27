"""
Comprehensive Test Suite for `disputearb` (Project 14: Chargeback Dispute Arbiter).
"""

from __future__ import annotations

import copy
from decimal import Decimal

import pytest

from fastapi.testclient import TestClient

from disputearb.api import app
from disputearb.arbiter import (
    CLASS_FRIENDLY_FRAUD,
    CLASS_MERCHANT_FAULT,
    CLASS_TRUE_FRAUD,
    ChargebackArbiter,
    DisputeClaim,
)
from disputearb.bench import run_benchmark
from disputearb.optimizer import (
    ACTION_AUTO_REFUND,
    ACTION_FIGHT,
    ACTION_WRITE_OFF,
    compute_expected_net_recovery,
)
from disputearb.receipts import (
    CheckoutAuthLeaf,
    DeliveryProofLeaf,
    EvidencePacket,
    MerchantSigner,
    PostPurchaseUsageLeaf,
    UsageEvent,
    build_merkle_tree,
    compile_evidence_packet,
    hash_leaf,
    verify_evidence_packet,
    verify_inclusion_proof,
)
from disputearb.rules import (
    SECONDS_PER_DAY,
    HistoricalTransaction,
    evaluate_visa_ce30,
)


def _make_sample_packet(signer: MerchantSigner | None = None):
    if signer is None:
        signer = MerchantSigner()
    ts = 1_725_000_000
    auth = CheckoutAuthLeaf(
        txn_id="TXN-TEST-001",
        account_id="ACCT-9001",
        amount_inr=12500.0,
        three_ds_status="Y",
        eci="05",
        cavv="CAVV-9001-AUTH",
        device_id="DEV-IPHONE-9001",
        ip_address="49.36.100.10",
        avs_cvv_match=True,
        shipping_address_hash="addr_hash_blr_9001",
        timestamp=ts,
    )
    delivery = DeliveryProofLeaf(
        delivered=True,
        carrier_signed_gps="12.9716,77.5946",
        otp_verified_handoff=True,
        recipient_signature_hash="sig_hash_9001",
        delivery_timestamp=ts + 5400,
    )
    usage = PostPurchaseUsageLeaf(
        events=[
            UsageEvent(
                event_type="app_login",
                device_id="DEV-IPHONE-9001",
                ip_address="49.36.100.10",
                timestamp=ts + 10800,
            )
        ]
    )
    return compile_evidence_packet(auth, delivery, usage, signer=signer), signer


def test_ed25519_and_merkle_evidence_tree_verification():
    packet, signer = _make_sample_packet()
    res = verify_evidence_packet(packet, trusted_public_key_hex=signer.public_key_hex)
    assert res.valid is True
    assert res.merkle_valid is True
    assert res.signature_valid is True
    assert res.inclusion_proofs_valid is True
    assert res.tampered_leaves == []

    # Verify individual leaf inclusion proofs against Merkle root
    for leaf_name, leaf_hash in packet.leaf_hashes.items():
        proof = packet.inclusion_proofs[leaf_name]
        assert verify_inclusion_proof(leaf_hash, proof, packet.merkle_root) is True


def test_tampering_any_field_breaks_verification_immediately():
    packet, signer = _make_sample_packet()

    # 1. Tamper IP address
    p_ip = copy.deepcopy(packet)
    p_ip.checkout_auth.ip_address = "203.0.113.55"
    r_ip = verify_evidence_packet(p_ip, trusted_public_key_hex=signer.public_key_hex)
    assert r_ip.valid is False
    assert "checkout_auth" in r_ip.tampered_leaves

    # 2. Tamper device_id
    p_dev = copy.deepcopy(packet)
    p_dev.checkout_auth.device_id = "DEV-TAMPERED"
    r_dev = verify_evidence_packet(p_dev, trusted_public_key_hex=signer.public_key_hex)
    assert r_dev.valid is False
    assert "checkout_auth" in r_dev.tampered_leaves

    # 3. Tamper 3DS2 status
    p_3ds = copy.deepcopy(packet)
    p_3ds.checkout_auth.three_ds_status = "N"
    r_3ds = verify_evidence_packet(p_3ds, trusted_public_key_hex=signer.public_key_hex)
    assert r_3ds.valid is False
    assert "checkout_auth" in r_3ds.tampered_leaves

    # 4. Tamper delivery OTP flag
    p_otp = copy.deepcopy(packet)
    p_otp.delivery_proof.otp_verified_handoff = False
    r_otp = verify_evidence_packet(p_otp, trusted_public_key_hex=signer.public_key_hex)
    assert r_otp.valid is False
    assert "delivery_proof" in r_otp.tampered_leaves

    # 5. Recompute Merkle tree after tampering without Ed25519 private key
    p_recomp = copy.deepcopy(p_otp)
    new_leaves = {
        "checkout_auth": hash_leaf("checkout_auth", p_recomp.checkout_auth.to_dict()),
        "delivery_proof": hash_leaf("delivery_proof", p_recomp.delivery_proof.to_dict()),
        "post_purchase_usage": hash_leaf("post_purchase_usage", p_recomp.post_purchase_usage.to_dict()),
    }
    new_root, new_proofs = build_merkle_tree(new_leaves)
    p_recomp.leaf_hashes = new_leaves
    p_recomp.merkle_root = new_root
    p_recomp.inclusion_proofs = new_proofs
    r_recomp = verify_evidence_packet(p_recomp, trusted_public_key_hex=signer.public_key_hex)
    assert r_recomp.valid is False
    assert r_recomp.signature_valid is False


def test_visa_ce30_qualification_and_edge_cases():
    packet, _ = _make_sample_packet()
    ts = packet.checkout_auth.timestamp

    # 2 undisputed prior transactions aged 140d and 260d sharing IP, device_id, shipping_address_hash, account_id
    valid_ledger = [
        HistoricalTransaction(
            txn_id="HIST-CE-1",
            account_id="ACCT-9001",
            ip_address="49.36.100.10",
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=8400.0,
            timestamp=int(ts - 140 * SECONDS_PER_DAY),
            disputed=False,
        ),
        HistoricalTransaction(
            txn_id="HIST-CE-2",
            account_id="ACCT-9001",
            ip_address="49.36.100.99",  # different IP, but device_id + shipping_address_hash + account_id match (3 elements)
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=9200.0,
            timestamp=int(ts - 260 * SECONDS_PER_DAY),
            disputed=False,
        ),
    ]
    ce_ok = evaluate_visa_ce30(packet, valid_ledger)
    assert ce_ok.qualified is True
    assert ce_ok.qualifying_txn_ids == ["HIST-CE-1", "HIST-CE-2"]

    # Reject if one transaction is outside [120, 365] day window (e.g. 45 days old) or disputed
    invalid_ledger = [
        valid_ledger[0],
        HistoricalTransaction(
            txn_id="HIST-TOO-RECENT",
            account_id="ACCT-9001",
            ip_address="49.36.100.10",
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=5000.0,
            timestamp=int(ts - 45 * SECONDS_PER_DAY),
            disputed=False,
        ),
        HistoricalTransaction(
            txn_id="HIST-DISPUTED",
            account_id="ACCT-9001",
            ip_address="49.36.100.10",
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=5000.0,
            timestamp=int(ts - 200 * SECONDS_PER_DAY),
            disputed=True,
        ),
    ]
    ce_fail = evaluate_visa_ce30(packet, invalid_ledger)
    assert ce_fail.qualified is False
    assert len(ce_fail.qualifying_txn_ids) == 1


def test_reason_codes_arbiter_and_ev_optimizer():
    packet, signer = _make_sample_packet()
    ts = packet.checkout_auth.timestamp
    ledger = [
        HistoricalTransaction(
            txn_id="HIST-A",
            account_id="ACCT-9001",
            ip_address="49.36.100.10",
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=7000.0,
            timestamp=int(ts - 150 * SECONDS_PER_DAY),
            disputed=False,
        ),
        HistoricalTransaction(
            txn_id="HIST-B",
            account_id="ACCT-9001",
            ip_address="49.36.100.10",
            device_id="DEV-IPHONE-9001",
            shipping_address_hash="addr_hash_blr_9001",
            amount_inr=9000.0,
            timestamp=int(ts - 220 * SECONDS_PER_DAY),
            disputed=False,
        ),
    ]
    arbiter = ChargebackArbiter(trusted_public_key_hex=signer.public_key_hex)

    # 1. Friendly fraud on Visa 10.4 -> FIGHT_REPRESENTMENT
    claim_ff = DisputeClaim(
        dispute_id="DSP-FF-1",
        txn_id=packet.txn_id,
        reason_code="10.4",
        amount_inr=12500.0,
        cardholder_statement="Cardholder claims unauthorized transaction.",
    )
    dec_ff = arbiter.evaluate_dispute(claim_ff, packet, historical_ledger=ledger)
    assert dec_ff.classification == CLASS_FRIENDLY_FRAUD
    assert dec_ff.recommended_action == ACTION_FIGHT
    assert dec_ff.ev_optimization.expected_net_recovery_inr > 10000.0
    assert packet.leaf_hashes["checkout_auth"] in dec_ff.representment_brief.markdown_brief
    assert "HIST-A" in dec_ff.representment_brief.markdown_brief

    # 2. Micro-ticket Friendly Fraud where fees exceed recovery -> ACCEPT_WRITE_OFF
    claim_micro = DisputeClaim(
        dispute_id="DSP-FF-MICRO",
        txn_id=packet.txn_id,
        reason_code="10.4",
        amount_inr=180.0,
        cardholder_statement="Micro ticket dispute.",
    )
    dec_micro = arbiter.evaluate_dispute(claim_micro, packet, historical_ledger=ledger)
    assert dec_micro.classification == CLASS_FRIENDLY_FRAUD
    assert dec_micro.recommended_action == ACTION_WRITE_OFF
    assert dec_micro.ev_optimization.expected_net_recovery_inr < 0.0

    # 3. Merchant fulfillment fault on Visa 13.1 / RuPay U14 -> AUTO_REFUND_PRE_DISPUTE
    undelivered_auth = copy.deepcopy(packet.checkout_auth)
    undelivered_proof = DeliveryProofLeaf(
        delivered=False,
        carrier_signed_gps="",
        otp_verified_handoff=False,
        recipient_signature_hash="",
        delivery_timestamp=0,
    )
    undelivered_pkt = compile_evidence_packet(
        undelivered_auth, undelivered_proof, PostPurchaseUsageLeaf(events=[]), signer=signer
    )
    claim_u14 = DisputeClaim(
        dispute_id="DSP-MF-U14",
        txn_id=undelivered_pkt.txn_id,
        reason_code="U14",
        amount_inr=4500.0,
        cardholder_statement="UPI debit completed but order never delivered.",
    )
    dec_u14 = arbiter.evaluate_dispute(claim_u14, undelivered_pkt, historical_ledger=[])
    assert dec_u14.classification == CLASS_MERCHANT_FAULT
    assert dec_u14.recommended_action == ACTION_AUTO_REFUND

    # 4. True third-party fraud on Mastercard 4837 -> ACCEPT_WRITE_OFF
    fraud_auth = CheckoutAuthLeaf(
        txn_id="TXN-TRUE-FRAUD",
        account_id="ACCT-9001",
        amount_inr=18000.0,
        three_ds_status="N",
        eci="07",
        cavv="",
        device_id="DEV-BURNER-99",
        ip_address="185.220.101.9",
        avs_cvv_match=False,
        shipping_address_hash="drop_addr",
        timestamp=ts,
    )
    fraud_pkt = compile_evidence_packet(
        fraud_auth, undelivered_proof, PostPurchaseUsageLeaf(events=[]), signer=signer
    )
    claim_4837 = DisputeClaim(
        dispute_id="DSP-TF-4837",
        txn_id="TXN-TRUE-FRAUD",
        reason_code="4837",
        amount_inr=18000.0,
        cardholder_statement="No cardholder authorization.",
    )
    dec_4837 = arbiter.evaluate_dispute(claim_4837, fraud_pkt, historical_ledger=[])
    assert dec_4837.classification == CLASS_TRUE_FRAUD
    assert dec_4837.recommended_action == ACTION_WRITE_OFF

    # Verify exact EV math formula
    ev_manual = compute_expected_net_recovery(Decimal("10000"), 0.90, Decimal("1200"), Decimal("250"))
    assert ev_manual == Decimal("0.90") * 10000 - Decimal("0.10") * 1200 - 250  # exact: money is Decimal


def test_300_dispute_benchmark_metrics():
    report = run_benchmark(num_cases=300, seed=20261014)
    assert report["total_disputes"] == 300
    assert report["tamper_detection_rate"] == 1.0
    assert report["ce30_friendly_fraud_catch_rate"] > 0.95

    net = {k: Decimal(v["total_net_recovery_inr"]) for k, v in report["strategies"].items()}
    ours = net["cryptographic_ev_arbiter"]

    assert ours > net["naive_fight_all"] + 150000
    assert ours > net["naive_amount_threshold_5000"] + 100000
    assert ours > net["unverified_evidence"] + 50000
    assert report["strategies"]["cryptographic_ev_arbiter"]["forged_packets_submitted"] == 0


def test_fastapi_endpoints():
    client = TestClient(app)

    # 1. GET /
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "Cryptographic Chargeback Dispute Arbiter" in r_root.text

    # 2. GET /disputes
    r_list = client.get("/disputes")
    assert r_list.status_code == 200
    data_list = r_list.json()
    assert data_list["count"] >= 10
    sample = _genuine_friendly_fraud(data_list["disputes"])

    # 3. POST /receipts/verify
    r_ver = client.post("/receipts/verify", json={"packet": sample["packet"]})
    assert r_ver.status_code == 200
    assert r_ver.json()["valid"] is True

    # 4. POST /disputes/evaluate
    r_eval = client.post(
        "/disputes/evaluate",
        json={
            "claim": sample["claim"],
            "packet": sample["packet"],
            "historical_ledger": sample["historical_ledger"],
        },
    )
    assert r_eval.status_code == 200
    assert r_eval.json()["classification"] == CLASS_FRIENDLY_FRAUD

    # 5. GET /bench
    r_bench = client.get("/bench")
    assert r_bench.status_code == 200
    b_json = r_bench.json()
    assert b_json["tamper_detection_rate"] == 1.0
    assert b_json["ce30_friendly_fraud_catch_rate"] > 0.95


def test_resigned_forgery_fails_against_the_pinned_merchant_key():
    packet, signer = _make_sample_packet()
    attacker = MerchantSigner.generate_random()
    forged = compile_evidence_packet(
        packet.checkout_auth, packet.delivery_proof, packet.post_purchase_usage, signer=attacker
    )
    # Internally consistent and carries the attacker's key, but the verifier ignores that key
    assert verify_evidence_packet(forged, trusted_public_key_hex=attacker.public_key_hex).valid is True
    assert verify_evidence_packet(forged, trusted_public_key_hex=signer.public_key_hex).valid is False

    sample = _genuine_friendly_fraud(TestClient(app).get("/disputes").json()["disputes"])
    forged_api = compile_evidence_packet(
        EvidencePacket.from_dict(sample["packet"]).checkout_auth,
        EvidencePacket.from_dict(sample["packet"]).delivery_proof,
        EvidencePacket.from_dict(sample["packet"]).post_purchase_usage,
        signer=attacker,
    )
    client = TestClient(app)
    body = {"claim": sample["claim"], "packet": forged_api.to_dict(),
            "trusted_public_key_hex": attacker.public_key_hex}
    assert client.post("/disputes/evaluate", json=body).json()["verification"]["valid"] is False


def test_ce30_needs_ip_or_device_among_the_matches():
    packet, _ = _make_sample_packet()
    ts = packet.checkout_auth.timestamp
    # Account and shipping address match, but IP and device differ: not CE 3.0
    ledger = [
        HistoricalTransaction(
            txn_id=f"HIST-ACCT-{k}",
            account_id=packet.checkout_auth.account_id,
            ip_address=f"10.0.0.{k}",
            device_id=f"OTHER-DEVICE-{k}",
            shipping_address_hash=packet.checkout_auth.shipping_address_hash,
            amount_inr=1000.0,
            timestamp=int(ts - (150 + k * 50) * SECONDS_PER_DAY),
        )
        for k in range(2)
    ]
    assert evaluate_visa_ce30(packet, ledger).qualified is False


def test_from_dict_rejects_strings_for_booleans_and_nan_amounts():
    hist = {"txn_id": "H", "account_id": "A", "ip_address": "1.2.3.4", "device_id": "D",
            "shipping_address_hash": "S", "timestamp": 1, "disputed": "false"}
    with pytest.raises(ValueError):
        HistoricalTransaction.from_dict(hist)  # bool("false") would have been True
    with pytest.raises(ValueError):
        DisputeClaim.from_dict({"dispute_id": "D", "txn_id": "T", "reason_code": "10.4", "amount_inr": "nan"})


def test_api_key_and_limits(monkeypatch):
    import importlib
    import json

    import disputearb.api as api

    monkeypatch.setenv("DISPUTEARB_API_KEYS", json.dumps({"s3cret": {"user": "ops", "role": "admin"}}))
    api = importlib.reload(api)
    client = TestClient(api.app)
    assert client.get("/disputes").status_code == 401
    assert client.get("/bench").status_code == 401
    hdr = {"X-API-Key": "s3cret"}
    assert client.get("/disputes", headers=hdr).status_code == 200
    assert client.get("/bench?num_cases=10000000", headers=hdr).status_code == 422

    sample = client.get("/disputes", headers=hdr).json()["disputes"][0]
    body = {"claim": sample["claim"], "packet": sample["packet"]}
    before = api.store.count()
    for _ in range(5):
        assert client.post("/disputes/evaluate", json=body, headers=hdr).status_code == 200
    assert api.store.count() == before + 5  # kept in the database, not a bounded in-memory list
    assert len(client.get("/disputes?limit=3", headers=hdr).json()["disputes"]) == 3
    assert client.get("/disputes?limit=5000", headers=hdr).status_code == 422


def _genuine_friendly_fraud(disputes):
    return next(d for d in disputes if d["tamper_mode"] == "none" and d["ground_truth_category"] == CLASS_FRIENDLY_FRAUD)
