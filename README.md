# Chargeback Dispute Arbiter

Given a chargeback and the merchant's evidence, this decides whether the merchant should fight it, accept it or refund before it escalates, and writes the representment brief.

Merchants lose disputes they could win, usually "friendly fraud" where the cardholder did make the purchase, and spend fees fighting ones they can't. Evidence put together after the fact can also be edited, which issuers rightly distrust.

## Features

- Signed evidence receipts: checkout, delivery and usage records are hashed into a Merkle tree and signed with Ed25519, so any later change is detected.
- Reason-code rules for Visa 10.4, 13.1, 13.3, 13.6 and 13.7, Mastercard 4837 and 4853, and RuPay/UPI U10 and U14, including Visa's Compelling Evidence 3.0 check.
- Classification into friendly fraud, true fraud, merchant fault or tampered evidence.
- An expected-value decision (fight, accept or refund) and a Markdown or JSON brief that cites the evidence.
- Stored disputes with the outcome an analyst recorded.

How the receipts, rules and decision work is described in [docs/design.md](docs/design.md).

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                       # 27 tests
python -m disputearb bench                # benchmark below
python -m disputearb serve                # API and console on http://127.0.0.1:8014
```

To build the container image: `docker build -t chargeback-dispute-arbiter .` (see [docs/runbook.md](docs/runbook.md)).

## API

| Endpoint | Purpose |
|---|---|
| `POST /disputes/evaluate` | classify a claim with its evidence and optional transaction history; returns and stores the decision and brief |
| `POST /receipts/verify` | verify an evidence packet against the merchant's public key |
| `GET /disputes`, `/disputes/{ref}` | stored disputes, newest first |
| `POST /disputes/{ref}/review` | record what was done: represented, written off or refunded |
| `GET /bench` | the benchmark (admin only) |
| `GET /healthz`, `/readyz`, `/metrics` | health, readiness and Prometheus metrics |

Amounts are rupees with at most two decimal places, handled as exact decimals and stored as integer paise. API keys carry a role: `intake`, `viewer`, `analyst`, `monitor` or `admin`. Create one with `python -m disputearb.ops keygen`.

## Results

On 300 generated disputes, the arbiter recovers ₹12.9 lakh against ₹10.1 lakh for fighting everything, and it never submits a tampered packet. Every tampered packet was detected.

These numbers are circular: the disputes are generated to match the arbiter's own rules, and fought disputes are scored with its own hand-set win probabilities. No public dataset of chargeback outcomes exists, so the win probabilities need to come from real representment history before the money figures mean anything. Details are in [docs/design.md](docs/design.md).

## Configuration

| Variable | Purpose |
|---|---|
| `DISPUTEARB_ENV=production` | refuse to start without API keys, a database and the merchant's public key |
| `DISPUTEARB_MERCHANT_PUBLIC_KEY` | key used to verify evidence (64 hex characters) |
| `DISPUTEARB_SIGNING_KEY` | development only: signs the sample disputes; refused in production |
| `DISPUTEARB_API_KEYS` / `DISPUTEARB_KEYS_FILE` | hashed API keys with roles |
| `DISPUTEARB_DATABASE_URL` | `sqlite:///...` or `postgresql://...` |

In production the service refuses to hold the merchant's signing key: signing belongs at checkout, not in the system that judges the evidence.

## Limitations

- The merchant signs its own evidence. The signature proves the packet hasn't changed, not that the 3-D Secure result, delivery or usage records are true. For evidence an issuer could rely on, each record would need signing by its source at the time of the event.
- Nothing is filed with Visa, Mastercard or NPCI, and the reason-code rules are simplified from public descriptions.
- The win probabilities are hand-set and the benchmark is circular.
- There is no case assignment or network deadline tracking.
- The code has not had an independent security review.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
