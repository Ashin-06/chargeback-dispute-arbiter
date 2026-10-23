# Chargeback Dispute Arbiter (`disputearb`)

Given a chargeback and the merchant's evidence, this decides whether the merchant should fight it (representment), accept it, or refund before it escalates. It does four things:

1. **Signed evidence receipts.** Checkout, delivery and post-purchase usage records go into a three-leaf SHA-256 Merkle tree, and the root is signed with Ed25519 (from `cryptography`). Any change to a field after signing breaks verification.
2. **Reason-code rules** for Visa 10.4, 13.1, 13.3, 13.6 and 13.7, Mastercard 4837 and 4853, and RuPay/UPI U10 and U14, including a Visa Compelling Evidence 3.0 check for 10.4.
3. **A classifier** that sorts each dispute into friendly fraud, true third-party fraud, merchant fault, or tampered evidence.
4. **An expected-value decision**: E[net] = P(win)·amount − (1 − P(win))·arbitration fee − filing fee, plus a Markdown/JSON representment brief that cites the leaf hashes and the CE 3.0 matches.

## How it works

**Receipts** (`receipts.py`). Leaves are hashed as `SHA-256(0x00 ‖ name ‖ ":" ‖ canonical JSON)` and internal nodes as `SHA-256(0x01 ‖ left ‖ right)`. The signature covers `DISPUTEARB_RECEIPT_V1|txn_id|root`. Verification recomputes every leaf and the root, checks the inclusion proofs, and checks the signature **against a merchant public key the verifier already holds**. The key inside the packet is never trusted, because anyone can re-sign altered evidence with their own key (there is a test for that). `MerchantSigner()` creates a random key unless you load one, for example from `DISPUTEARB_SIGNING_KEY`.

**CE 3.0** (`rules.py`). The disputed transaction qualifies when there are at least two prior undisputed transactions aged 120–365 days, each sharing at least two of IP address, device ID, shipping address and account ID with it, and at least one of the matches is the IP or the device. Ages are measured from the disputed transaction, and the ledger is assumed to hold transactions on the same card. For Mastercard and UPI fraud codes the same footprint counts as supporting evidence, but it is not labelled CE 3.0.

**Win probability** (`optimizer.py`). These are **hand-set weights**: for example, friendly fraud starts at 0.72, adds 0.16 for CE 3.0 and 0.08 for 3DS ECI 05, and is capped at 0.97. They are judgement calls, not fitted to any dispute outcomes. Before the EV numbers mean anything, the weights should be replaced with win rates measured from real representment history.

## Results

`python -m disputearb bench` runs 300 synthetic disputes: 135 friendly fraud (65 of them Visa 10.4 with CE 3.0 history), 66 true fraud, 54 merchant faults and 45 tampered packets.

| Strategy | Fought | Written off | Refunded | Forged packets submitted | Net recovery (₹) |
|---|---|---|---|---|---|
| This arbiter | 126 | 120 | 54 | 0 | 1,286,465 |
| Fight everything | 300 | 0 | 0 | 45 | 1,007,698 |
| Fight if ≥ ₹5,000 | 201 | 99 | 0 | 45 | 876,306 |
| Same rules, signatures not checked | 171 | 75 | 54 | 45 | 1,153,715 |

Tampering is detected in 45/45 cases, CE 3.0 qualifies in 65/65, and classification accuracy is 100%.

**These numbers are circular. Do not read them as evidence the arbiter recovers more money.**
- The generator builds each case to match the arbiter's own rules, so 100% accuracy is by construction.
- A fought dispute is scored with the arbiter's own P(win), so a strategy that maximises EV under those probabilities beats the others by definition. A pre-dispute refund is credited an assumed ₹150.
- The tampered packets are edited after signing without re-signing, so any hash check catches them. Re-signing with another key is also caught, but only because the verifier pins the merchant key.

No public dataset of chargebacks with representment outcomes exists. Public fraud datasets (for example IEEE-CIS, or the European card dataset) carry fraud labels but no dispute or representment results, so they cannot test this.

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                       # 10 tests
python -m disputearb bench                # the table above
python -m disputearb serve --port 8014    # API + console at http://127.0.0.1:8014
```

| Endpoint | |
|---|---|
| `GET /disputes` | 20 sample disputes plus the most recent evaluations (the latest 200 are kept) |
| `POST /disputes/evaluate` | classify a claim + evidence packet + optional ledger, and return the decision and brief |
| `POST /receipts/verify` | verify a packet against the server's merchant key |
| `GET /bench?num_cases=` | the benchmark, 10–2000 cases |

Set `DISPUTEARB_API_KEY` to require it in the `X-API-Key` header (the console has a field for it), and `DISPUTEARB_SIGNING_KEY` (64 hex characters) to use a fixed merchant key. Without the API key the server runs open, and `serve` refuses to bind a non-loopback address. POST bodies are capped at 1 MB.

## Limits

- **The merchant signs its own evidence.** The signature proves the packet hasn't changed since the merchant's key signed it. It does not prove the 3DS result, the delivery or the usage events are true, and a merchant can sign anything at any time. For evidence an issuer could rely on, each record would need signing by its source at the time of the event (3DS server, carrier, app backend), with trusted timestamps.
- **No network integration.** Nothing is filed with Visa, Mastercard or NPCI. Reason codes, fees and rules are simplified from public descriptions, and only Visa ECI values (05/06/07) are modelled; Mastercard uses 02/01.
- **Uncalibrated P(win) and a circular benchmark.** See above.
- **Rule details are approximations.** The CE 3.0 age window is measured from the transaction date, and other Visa conditions are not checked (same card, merchant-provided descriptions, exclusions).
- **Synthetic data only.** All 300 cases and the sample disputes are generated.
- **No deployment story**: no TLS, rate limiting, key management service, persistence or audit log. The dispute store is in memory.
