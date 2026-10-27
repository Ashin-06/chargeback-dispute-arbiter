# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with a `disputearb` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `DISPUTEARB_*` environment variables, checked at startup.
  `DISPUTEARB_ENV=production` refuses to start without hashed API keys, a database and
  `DISPUTEARB_MERCHANT_PUBLIC_KEY`, and refuses to start if it is also given
  `DISPUTEARB_SIGNING_KEY`. No demo disputes are seeded in production.
- Per-client API keys with roles (`intake`, `viewer`, `analyst`, `monitor`, `admin`), stored as
  `sha256:<hex>`; `python -m disputearb.ops keygen` makes new ones. Replaces `DISPUTEARB_API_KEY`.
- Dispute store in SQLite or Postgres (`DISPUTEARB_DATABASE_URL`) with numbered migrations and
  `python -m disputearb migrate`. `POST /disputes/evaluate` returns a `dispute_ref`;
  `GET /disputes/{ref}` and `POST /disputes/{ref}/review` record what was done with a note.
- Per-client rate limit, body cap (also for chunked bodies), security headers, CORS only for
  listed origins; JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus `/metrics`
  (`disputearb_decisions_total` by recommended action and review outcome).
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- **Money is `Decimal`, never float.** Amounts and fees are parsed into rupees with at most two
  decimal places (NaN, infinity, negatives and fractions of a paisa are refused), expected value
  and break-even are computed in `Decimal`, `to_dict()` returns amounts as exact decimal strings
  (`"4500.00"`), and the database stores integer paise. Leaf hashing serialises amounts the same
  way however they were entered.
- The dispute store is the database instead of an in-memory list capped at 200.
- 400 responses name the bad field without echoing the submitted value; `/bench` needs the
  `admin` role.

### Unchanged
- The rules, classification and EV logic. Every benchmark number is identical before and after
  the move to `Decimal` (checked field by field on the 300-case run).
