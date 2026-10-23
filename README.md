# 14 — Cryptographic Chargeback Evidence Compiler, Friendly-Fraud (Visa CE 3.0) Arbiter & Expected-Value Representment Optimizer (`disputearb`)

A cryptographic dispute arbitration and representment optimization engine that compiles tamper-evident **Ed25519 + SHA-256 Merkle Evidence Receipts**, evaluates **Visa Compelling Evidence 3.0 (CE 3.0)** and card-network / RuPay-UPI reason-code rules, and maximizes **Expected Net Recovery ($\mathbb{E}[\text{Net}]$)** across chargeback claims.

---

## Architecture & Core Modules

1. **`disputearb/receipts.py` — Cryptographic Checkout & Fulfillment Receipts**
   - Generates and verifies tamper-evident `EvidencePacket` objects signed with `cryptography.hazmat.primitives.asymmetric.ed25519` over a domain-separated **SHA-256 Merkle Evidence Tree**:
     - **Leaf 1 (`checkout_auth`):** 3DS2 status (`Y`/`N`), `eci` (`05`/`06`/`07`), `cavv`, `device_id`, `ip_address`, `avs_cvv_match`, `shipping_address_hash`, `account_id`, `amount_inr`, `timestamp`.
     - **Leaf 2 (`delivery_proof`):** Carrier-signed GPS coordinates, OTP-verified handoff flag (`otp_verified_handoff`), recipient signature/photo hash, and `delivery_timestamp`.
     - **Leaf 3 (`post_purchase_usage`):** Authenticated app login and session telemetry from the same `device_id` / `ip_address` after the checkout timestamp.
   - Any post-signing mutation to IP address, device ID, 3DS2 status, or delivery OTP immediately breaks Merkle leaf hashes, inclusion proofs, and Ed25519 signature verification.

2. **`disputearb/rules.py` — Card-Network & RuPay/UPI Reason-Code Engine + Visa CE 3.0**
   - **Visa `10.4` (Other Fraud — Card-Absent Environment) & Visa CE 3.0:** Checks whether the customer has $\ge 2$ prior undisputed transactions aged $120\text{--}365$ days that share $\ge 2$ core elements (`ip_address`, `device_id`, `shipping_address_hash`, `account_id`) with the disputed transaction.
   - **Visa Consumer Disputes:** `13.1` (Merchandise/Services Not Received), `13.3` (Not as Described), `13.6` (Credit Not Processed), `13.7` (Cancelled Recurring).
   - **Mastercard:** `4837` (No Cardholder Authorization), `4853` (Cardholder Dispute).
   - **RuPay / UPI:** `U10` (Unauthorised UPI Debit), `U14` (Goods/Services Not Provided).

3. **`disputearb/arbiter.py` & `disputearb/optimizer.py` — 4-Class Arbiter & EV Optimizer**
   - Classifies every dispute into:
     - `first_party_friendly_fraud`
     - `true_third_party_fraud`
     - `merchant_fulfillment_fault`
     - `tampered_evidence_rejected`
   - Computes calibrated win probability $P(\text{win} \mid \text{evidence}, \text{reason\_code})$ and **Expected Net Recovery**:
     $$\mathbb{E}[\text{Net}] = P(\text{win}) \cdot \text{Amount} - (1 - P(\text{win})) \cdot \text{NetworkArbitrationFee} - \text{RepresentmentFilingFee}$$
   - Recommends `FIGHT_REPRESENTMENT`, `ACCEPT_WRITE_OFF`, or `AUTO_REFUND_PRE_DISPUTE`, and compiles a structured Markdown + JSON **Representment Evidence Brief** citing exact SHA-256 Merkle leaf hashes and Visa CE 3.0 historical transaction IDs.

4. **`disputearb/bench.py` — 300-Dispute Synthetic Benchmark**
   - Evaluates 300 synthetic disputes across all 4 categories and 9 reason codes, comparing `cryptographic_ev_arbiter` against:
     - `naive_fight_all`
     - `naive_amount_threshold_5000` (`fight if amount >= ₹5,000`)
     - `unverified_evidence` (accepts tampered payloads without Ed25519/Merkle checks)

---

## Quickstart & CLI

```bash
# Run test suite
python -m pytest -q

# Run 300-dispute benchmark
python -m disputearb bench

# Start FastAPI server + interactive Web Console on port 8014
python -m disputearb serve --port 8014
```

---

## 300-Dispute Synthetic Benchmark Results

```text
======================================================================================
  CRYPTOGRAPHIC CHARGEBACK DISPUTE ARBITER (VISA CE 3.0 & EV OPTIMIZER) BENCHMARK
======================================================================================
Total Synthetic Disputes Evaluated : 300
Tamper Detection Rate (Ed25519+Mkl): 100.00% (45/45)
Visa CE 3.0 Friendly-Fraud Catch   : 100.00% (65/65)
Overall 4-Class Arbiter Accuracy   : 100.00%
--------------------------------------------------------------------------------------
Strategy                         | Fought | WriteOff | AutoRef | ForgedSub | Net Recovery (INR)
--------------------------------------------------------------------------------------
cryptographic_ev_arbiter         |    126 |      120 |      54 |         0 | INR   1,286,465.42
naive_fight_all                  |    300 |        0 |       0 |        45 | INR   1,007,697.69
naive_amount_threshold_5000      |    201 |       99 |       0 |        45 | INR     876,305.84
unverified_evidence              |    171 |       75 |      54 |        45 | INR   1,153,715.42
--------------------------------------------------------------------------------------
Net Recovery Uplift vs Naive Fight-All         : +INR 278,767.73
Net Recovery Uplift vs Naive Amount >= 5,000   : +INR 410,159.58
Net Recovery Uplift vs Unverified Evidence     : +INR 132,750.00
======================================================================================
```
