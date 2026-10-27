# Runbook

How to deploy, configure and operate the dispute arbiter. Commands assume the repository root.

## Deploy

```bash
docker build -t chargeback-dispute-arbiter:1.0.0 .
python -m disputearb.ops keygen               # one key per intake system, analyst and monitor
docker run -d --name disputearb -p 8014:8014 -v disputearb-data:/data \
  -e DISPUTEARB_KEYS_FILE=/run/secrets/disputearb-keys.json \
  -e DISPUTEARB_MERCHANT_PUBLIC_KEY=<64 hex> \
  chargeback-dispute-arbiter:1.0.0
curl -fsS http://127.0.0.1:8014/readyz
```

The image runs in production mode as a non-root user with its SQLite database in `/data`. It refuses
to start, and logs why, without keys, a database or the merchant's public key, or if it is given
`DISPUTEARB_SIGNING_KEY`. Get the public key from the team that holds the signing key
(`MerchantSigner(...).public_key_hex`). Terminate TLS in front of it. For several replicas use Postgres.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `disputearb serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `DISPUTEARB_ENV` | — | `development` (default) or `production` |
| `DISPUTEARB_API_KEYS` / `DISPUTEARB_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `intake` (evaluate, verify), `viewer` (read), `analyst` (evaluate, read, review), `monitor` (`/metrics`), `admin` (all, plus `/bench`) |
| `DISPUTEARB_MERCHANT_PUBLIC_KEY` | yes | Ed25519 public key evidence must verify against, 64 hex |
| `DISPUTEARB_DATABASE_URL` | yes | `sqlite:////data/disputearb.db` or `postgresql://...` (development default: in memory) |
| `DISPUTEARB_SIGNING_KEY` | must be unset | development only: seed for the demo key that signs sample disputes |
| `DISPUTEARB_HOST`, `DISPUTEARB_PORT` | — | default `127.0.0.1:8014`; a non-loopback address needs API keys |
| `DISPUTEARB_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `DISPUTEARB_MAX_BODY_BYTES` | — | default 1,000,000 |
| `DISPUTEARB_CORS_ORIGINS` | — | origins allowed to call from a browser; none by default |
| `DISPUTEARB_LOG_LEVEL` | — | default `INFO` |

## Watch

- `GET /healthz`: process up. `GET /readyz`: database answers.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `disputearb_decisions_total{decision="FIGHT_REPRESENTMENT|ACCEPT_WRITE_OFF|AUTO_REFUND_PRE_DISPUTE|review_*"}`.
- Logs: JSON lines with `request_id`, also returned in `X-Request-ID`.

Suggested alerts: `/readyz` failing; 5xx rising; a jump in packets failing verification (shows as
`ACCEPT_WRITE_OFF` with "Cryptographic verification failed" in the rationale: a key mismatch after
a rotation, or forgery attempts); open disputes close to the network's response deadline.

## Rotate keys

**API keys.** Add the new hash, restart, hand over the new key, remove the old hash, restart.

**Merchant key.** The checkout side starts signing with the new key on a date; evidence signed
before then still needs the old public key. The service pins one key, so run the rotation in two
steps: keep the old public key until disputes on old evidence have aged out of the network's
dispute window (120 days for most reason codes), or run a second instance with the old key for
those. If the old signing key leaked, switch at once and treat old evidence as unverifiable.

## Back up and restore

SQLite (in the `/data` volume):

```bash
docker exec disputearb python -c "import sqlite3; s=sqlite3.connect('/data/disputearb.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp disputearb:/data/backup.db ./disputearb-$(date +%F).db
```

Restore: stop the container, put the backup at `/data/disputearb.db`, start it, check `/readyz` and
`GET /disputes`. Postgres: `pg_dump` / `pg_restore`; migrations run on start or with
`python -m disputearb migrate`. Backups hold cardholder data: encrypt them and limit access.

## Incidents

1. **Merchant signing key leaked.** Rotate it on the checkout side, set the new public key here and
   restart. Re-check disputes fought on evidence signed since the leak.
2. **Verification suddenly fails for everything.** Usually the public key doesn't match the
   signing key in use. Compare with the checkout team before fighting or writing off anything.
3. **Leaked API key.** Remove its hash and restart; review that user's submissions and outcomes.
4. **Database lost.** Restore the latest backup and re-submit disputes received since then from
   the intake queue.
