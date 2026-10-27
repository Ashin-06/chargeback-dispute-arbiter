"""Settings, the merchant-key rules, money as Decimal, auth, limits, headers, metrics, health,
the stored disputes and migrations."""
import hashlib
import importlib
import json
import os
import subprocess
import sys
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from disputearb import db, ops
from disputearb.arbiter import DisputeClaim
from disputearb.receipts import MerchantSigner, as_amount

KEY = "disputearb_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "intake-1", "role": "intake"}}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("DISPUTEARB_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"DISPUTEARB_{k}", v)
    import disputearb.api as api

    return importlib.reload(api)


def genuine(c, headers=None):
    ds = c.get("/disputes", params={"limit": 1000}, headers=headers or {}).json()["disputes"]
    return next(d for d in ds if d["tamper_mode"] == "none" and d["ground_truth_category"] == "first_party_friendly_fraud")


@pytest.mark.parametrize("change, message", [
    ({"DISPUTEARB_API_KEYS": None}, "API keys"),
    ({"DISPUTEARB_DATABASE_URL": None}, "DATABASE_URL"),
    ({"DISPUTEARB_API_KEYS": json.dumps({KEY: {"user": "p", "role": "intake"}})}, "sha256"),
    ({"DISPUTEARB_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"DISPUTEARB_CORS_ORIGINS": "*"}, "CORS"),
    ({"DISPUTEARB_ENV": "prod"}, "development or production"),
])
def test_production_settings_refused(change, message):
    env = {"DISPUTEARB_ENV": "production", "DISPUTEARB_API_KEYS": json.dumps(HASHED), "DISPUTEARB_DATABASE_URL": "sqlite://"}
    env.update(change)
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings({k: v for k, v in env.items() if v is not None})


def test_production_pins_the_merchant_public_key(monkeypatch):
    base = {"ENV": "production", "API_KEYS": json.dumps(HASHED), "DATABASE_URL": "sqlite://"}
    signer = MerchantSigner.generate_random()
    with pytest.raises(ops.ConfigError, match="MERCHANT_PUBLIC_KEY"):
        boot(monkeypatch, **base)
    with pytest.raises(ops.ConfigError, match="signing key"):
        boot(monkeypatch, **base, MERCHANT_PUBLIC_KEY=signer.public_key_hex, SIGNING_KEY="11" * 32)
    with pytest.raises(ops.ConfigError, match="64 hex"):
        boot(monkeypatch, **base, MERCHANT_PUBLIC_KEY="zz" * 32)
    api = boot(monkeypatch, **base, MERCHANT_PUBLIC_KEY=signer.public_key_hex)
    assert api.store.count() == 0  # no demo disputes in production
    assert api.TRUSTED_PUBLIC_KEY == signer.public_key_hex


def test_amounts_are_decimal_paise():
    assert as_amount(1234.5) == Decimal("1234.50") and as_amount("0.10") == Decimal("0.10")
    # floats are read via str(): 0.1 + 0.2 is 0.30000000000000004, which is not a paise amount
    for bad in ("nan", "inf", -1, "1.005", True, "abc", 0.1 + 0.2):
        with pytest.raises(ValueError):
            as_amount(bad)
    claim = DisputeClaim("D1", "T1", "10.4", 19.99, "x", network_arbitration_fee_inr="1200")
    assert claim.amount_inr == Decimal("19.99") and claim.to_dict()["amount_inr"] == "19.99"
    assert claim.network_arbitration_fee_inr == Decimal("1200.00")


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"DISPUTEARB_HOST": "0.0.0.0"})


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("DISPUTEARB_")}
    r = subprocess.run([sys.executable, "-m", "disputearb", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    keys = {"k-in": {"user": "intake-1", "role": "intake"}, "k-view": {"user": "vic", "role": "viewer"},
            "k-an": {"user": "asha", "role": "analyst"}, "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    sample = genuine(c, {"x-api-key": "k-view"})
    body = {"claim": sample["claim"], "packet": sample["packet"]}
    assert c.post("/disputes/evaluate", json=body).status_code == 401
    assert c.post("/disputes/evaluate", json=body, headers={"x-api-key": "k-in"}).status_code == 200
    assert c.get("/disputes", headers={"x-api-key": "k-in"}).status_code == 403
    assert c.post("/disputes/evaluate", json=body, headers={"x-api-key": "k-view"}).status_code == 403
    assert c.post(f"/disputes/{sample['id']}/review", json={"status": "represented", "note": "sent"},
                  headers={"x-api-key": "k-view"}).status_code == 403
    assert c.get("/bench", headers={"x-api-key": "k-an"}).status_code == 403  # admin only: CPU-heavy
    assert c.get("/metrics", headers={"x-api-key": "k-an"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and "disputearb_decisions_total" in m.text


def test_disputes_are_stored_reviewed_and_survive_a_restart(monkeypatch, tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'disputes.db'}"
    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)
    sample = genuine(c)
    out = c.post("/disputes/evaluate", json={"claim": sample["claim"], "packet": sample["packet"],
                                             "historical_ledger": sample["historical_ledger"]}).json()
    ref = out["dispute_ref"]
    rev = c.post(f"/disputes/{ref}/review", json={"status": "represented", "note": "CE 3.0 brief filed"})
    assert rev.status_code == 200 and rev.json()["status"] == "represented"
    assert c.post(f"/disputes/{ref}/review", json={"status": "won", "note": "xx"}).status_code == 422
    assert c.post("/disputes/nope/review", json={"status": "refunded", "note": "xx"}).status_code == 404

    seeded_ids = {d["id"] for d in c.get("/disputes", params={"limit": 1000}).json()["disputes"]}
    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)  # restart: the seed isn't repeated
    after = c.get("/disputes", params={"limit": 1000}).json()["disputes"]
    assert {d["id"] for d in after} == seeded_ids
    got = c.get(f"/disputes/{ref}").json()
    assert got["status"] == "represented" and got["reviews"][0]["note"] == "CE 3.0 brief filed"
    assert got["amount_paise"] == int(Decimal(sample["claim"]["amount_inr"]) * 100)
    assert got["claim"]["amount_inr"] == sample["claim"]["amount_inr"]  # exact decimal string
    assert c.get("/disputes", params={"status": "represented"}).json()["count"] >= 1


def test_errors_do_not_leak(monkeypatch):
    api = boot(monkeypatch)

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: card 4111111111111111")

    c = TestClient(api.app)
    crash = c.get("/boom")
    assert crash.status_code == 500 and "4111" not in crash.text and crash.json()["request_id"]
    sample = genuine(c)
    claim = {**sample["claim"], "amount_inr": "SECRET-AMOUNT"}
    bad = c.post("/disputes/evaluate", json={"claim": claim, "packet": sample["packet"]})
    assert bad.status_code == 400 and "SECRET" not in bad.text
    missing = c.post("/disputes/evaluate", json={"packet": sample["packet"]})
    assert missing.status_code == 400 and "claim" in missing.text


def test_rate_limit_body_cap_and_headers(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/disputes").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    c = TestClient(boot(monkeypatch, MAX_BODY_BYTES="500").app)
    assert c.post("/receipts/verify", json={"packet": {"x": "y" * 600}}).status_code == 413

    def chunks():
        for _ in range(10):
            yield b"a" * 100

    assert c.post("/receipts/verify", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    r = c.get("/disputes", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123" and r.headers["content-security-policy"] == ops.API_CSP
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert "access-control-allow-origin" not in c.get("/disputes", headers={"origin": "https://evil.example"}).headers


def test_health_and_readiness(monkeypatch):
    api = boot(monkeypatch)
    c = TestClient(api.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json()["checks"] == {"database": True}
    monkeypatch.setattr(api.store.db, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and "db down" not in r.text


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello")
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1"


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"] and db.migrate(eng) == []
    with eng.connect() as c:
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"disputes", "dispute_reviews", "schema_migrations"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("DISPUTEARB_")}, "DISPUTEARB_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "disputearb", "migrate"], env=env, capture_output=True, text=True,
                         timeout=120, check=False)
    assert out.returncode == 0 and "up to date" in out.stdout
