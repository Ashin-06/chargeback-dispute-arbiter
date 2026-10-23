"""
CLI Entrypoint for `disputearb`:
  - `python -m disputearb bench`
  - `python -m disputearb serve --port 8014`
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import uvicorn

from disputearb.bench import run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="disputearb",
        description="Cryptographic Chargeback Evidence Compiler, Visa CE 3.0 Arbiter & EV Optimizer",
    )
    sub = parser.add_subparsers(dest="command")

    bench_p = sub.add_parser("bench", help="Run the 300-dispute synthetic evaluation benchmark")
    bench_p.add_argument("--cases", type=int, default=300, help="Number of synthetic disputes, 10-100000 (default: 300)")
    bench_p.add_argument("--json", action="store_true", help="Print raw JSON output")

    serve_p = sub.add_parser("serve", help="Start the FastAPI server and interactive console")
    serve_p.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8014, help="Port number (default: 8014)")

    args = parser.parse_args(argv)
    if not 10 <= getattr(args, "cases", 300) <= 100_000:
        parser.error("--cases must be between 10 and 100000")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.command == "serve":
        if args.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("DISPUTEARB_API_KEY"):
            print("Refusing to listen on a non-loopback address without DISPUTEARB_API_KEY set.", file=sys.stderr)
            return 2
        uvicorn.run("disputearb.api:app", host=args.host, port=args.port, log_level="info")
        return 0

    # Default or "bench" command
    num_cases = getattr(args, "cases", 300)
    as_json = getattr(args, "json", False)
    report = run_benchmark(num_cases=num_cases)
    if as_json:
        print(json.dumps(report, indent=2))
        return 0

    print("=" * 86)
    print("  CRYPTOGRAPHIC CHARGEBACK DISPUTE ARBITER (VISA CE 3.0 & EV OPTIMIZER) BENCHMARK")
    print("=" * 86)
    print(f"Total Synthetic Disputes Evaluated : {report['total_disputes']}")
    print(f"Tamper Detection Rate (Ed25519+Mkl): {report['tamper_detection_rate'] * 100:.2f}% "
          f"({report['tampered_detected']}/{report['tampered_total']})")
    print(f"Visa CE 3.0 Friendly-Fraud Catch   : {report['ce30_friendly_fraud_catch_rate'] * 100:.2f}% "
          f"({report['ce30_caught']}/{report['ce30_total']})")
    print(f"Overall 4-Class Arbiter Accuracy   : {report['classification_accuracy'] * 100:.2f}%")
    print("-" * 86)
    print(f"{'Strategy':<32} | {'Fought':>6} | {'WriteOff':>8} | {'AutoRef':>7} | {'ForgedSub':>9} | {'Net Recovery (INR)':>18}")
    print("-" * 86)
    for name, st in report["strategies"].items():
        print(
            f"{name:<32} | {st['disputes_fought']:>6} | {st['disputes_written_off']:>8} | "
            f"{st['disputes_auto_refunded']:>7} | {st['forged_packets_submitted']:>9} | "
            f"INR {st['total_net_recovery_inr']:>14,.2f}"
        )
    print("-" * 86)
    uplift = report["net_recovery_uplift_inr"]
    print(f"Net Recovery Uplift vs Naive Fight-All         : +INR {uplift['vs_naive_fight_all']:,.2f}")
    print(f"Net Recovery Uplift vs Naive Amount >= 5,000   : +INR {uplift['vs_naive_amount_threshold_5000']:,.2f}")
    print(f"Net Recovery Uplift vs Unverified Evidence     : +INR {uplift['vs_unverified_evidence']:,.2f}")
    print("=" * 86)
    return 0


if __name__ == "__main__":
    sys.exit(main())
