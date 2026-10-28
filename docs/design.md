# Design

## Evidence receipts

`receipts.py`. Checkout, delivery and post-purchase usage records become the three leaves of a SHA-256 Merkle tree, and the root is signed with Ed25519 (from `cryptography`). Leaves are hashed as `SHA-256(0x00 ‖ name ‖ ":" ‖ canonical JSON)` and internal nodes as `SHA-256(0x01 ‖ left ‖ right)`. The signature covers `DISPUTEARB_RECEIPT_V1|txn_id|root`.

Verification recomputes every leaf and the root, checks the inclusion proofs and checks the signature against a merchant public key the verifier already holds. The key inside a packet is never trusted, because anyone could re-sign altered evidence with their own key; a test covers that case.

## Compelling Evidence 3.0

`rules.py`. A disputed Visa 10.4 transaction qualifies when there are at least two earlier undisputed transactions, 120–365 days old, that each share at least two of IP address, device ID, shipping address and account ID with it, and at least one of the matches is the IP or the device. Ages are measured from the disputed transaction, and the ledger is assumed to hold transactions on the same card. For Mastercard and UPI fraud codes the same history counts as supporting evidence but isn't labelled CE 3.0.

Rules exist for Visa 10.4, 13.1, 13.3, 13.6 and 13.7, Mastercard 4837 and 4853, and RuPay/UPI U10 and U14.

## Decision

`optimizer.py` estimates the chance of winning and computes the expected net:

E[net] = P(win) × amount − (1 − P(win)) × arbitration fee − filing fee

The win probabilities are hand-set weights. For example, friendly fraud starts at 0.72, adds 0.16 for CE 3.0 and 0.08 for 3-D Secure ECI 05, and is capped at 0.97. They are judgement calls, not fitted to dispute outcomes, and should be replaced with win rates measured from real representment history.

## Results

`python -m disputearb bench` runs 300 generated disputes: 135 friendly fraud (65 of them Visa 10.4 with CE 3.0 history), 66 true fraud, 54 merchant faults and 45 tampered packets.

| Strategy | Fought | Written off | Refunded | Forged packets submitted | Net recovery (₹) |
|---|---|---|---|---|---|
| This arbiter | 126 | 120 | 54 | 0 | 1,286,465 |
| Fight everything | 300 | 0 | 0 | 45 | 1,007,698 |
| Fight if ₹5,000 or more | 201 | 99 | 0 | 45 | 876,306 |
| Same rules, signatures not checked | 171 | 75 | 54 | 45 | 1,153,715 |

Tampering is detected in 45 of 45 cases, CE 3.0 qualifies in 65 of 65, and every dispute is classified correctly.

These numbers are circular and don't show that the arbiter recovers more money:
- the generator builds each case to match the arbiter's own rules, so perfect accuracy is by construction;
- fought disputes are scored with the arbiter's own win probabilities, so the strategy that maximises expected value under them wins by definition (a pre-dispute refund is credited an assumed ₹150);
- the tampered packets are edited after signing without re-signing, so any hash check catches them.

No public dataset records chargebacks with representment outcomes. Public fraud datasets such as IEEE-CIS or the European card dataset have fraud labels but no dispute results.
