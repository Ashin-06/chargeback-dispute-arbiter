# Threat model

What the dispute arbiter protects, from whom, and what is still open. Written for the 1.0.0 code;
nobody independent has reviewed it.

## What it protects

| Asset | Where it lives |
|---|---|
| Chargeback claims, evidence packets and purchase history (account IDs, IPs, device IDs, address hashes) | request bodies; the `disputes` table |
| Decisions and analysts' outcomes (fight, write off, refund) | `disputes`, `dispute_reviews` tables |
| The merchant's public key that evidence must verify against | `DISPUTEARB_MERCHANT_PUBLIC_KEY` |
| The merchant's signing key | **not here**: with the checkout systems that sign evidence |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

## Trust boundaries

```
checkout / carrier / app ──(sign evidence with the merchant key)──► evidence store
chargeback intake ──► disputearb API ──► database (disputes, outcomes)
analyst           ──►       ▲
```

1. **Evidence → arbiter.** Packets are untrusted until the Merkle root and the Ed25519 signature
   check out against the pinned public key. The key inside a packet is ignored.
2. **Callers → API.** `intake` keys only submit; `analyst` keys also read and record outcomes.
3. **API → database.** Holds evidence and outcomes in plain form.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| Altered evidence after signing | Leaf and root recomputed, inclusion proofs checked, signature checked | — |
| Evidence re-signed with another key | Verification uses only the pinned merchant key, never one from the packet or the caller | If the merchant's signing key leaks, forgeries verify until the key is rotated |
| The arbiter is compromised and forges evidence | Production refuses to hold the signing key | — |
| The merchant signs false evidence | — | **Not addressed.** A signature proves the packet hasn't changed, not that its contents are true. Needs source-signed, timestamped records (see README Limits). |
| Fighting a dispute that should be refunded, or the reverse | EV rule with documented assumptions; every outcome is recorded with the analyst's name | P(win) weights are hand-set; the benchmark is circular |
| Floating-point errors in money | Amounts and EV in `Decimal`; integer paise in storage; sub-paisa and non-finite values refused | — |
| Data leak of cardholder data | API keys with roles; 400s don't echo values; no CORS unless listed | Anyone with database access sees all stored evidence |
| An insider changes an outcome | Every review is stored with the reviewer and a note | Not tamper-evident against database write access |
| Flooding or CPU exhaustion | 1 MB body cap, per-client rate limit, `/bench` admin-only | Rate limit is per process |

## Not covered

- Card-network filing and deadlines (no integration).
- TLS (terminate it at the ingress).
- Key management: the public key comes from an environment variable; the signing key's HSM/KMS
  custody is the checkout side's job.
