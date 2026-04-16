#!/usr/bin/env python3
"""
demo.py  –  Interactive demonstration of the MPC-in-the-Head RSD protocol.

Usage
-----
    python demo.py [--mode {interactive,nizk,bench}] [--params {tiny,small,paper}]
                   [--kappa N] [--rounds N]

Examples
--------
    # Show one interactive round with tiny parameters (fast)
    python demo.py --mode interactive --params tiny

    # Generate and verify a NIZK proof with small parameters
    python demo.py --mode nizk --params small --kappa 20

    # Benchmark the interactive protocol (100 rounds)
    python demo.py --mode bench --params small --rounds 100
"""

import argparse
import time
import sys
from typing import Optional


def _banner(title: str) -> None:
    w = 70
    print()
    print("=" * w)
    print(f"  {title}")
    print("=" * w)


def _section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def demo_interactive(params_name: str) -> None:
    from mpci_head import generate_instance, Prover, Verifier, verify_witness
    from mpci_head.rsd import RSDParams

    param_map = {
        "tiny":  RSDParams.tiny(),
        "small": RSDParams.small(),
        "paper": RSDParams.paper_128(),
    }
    params = param_map[params_name]

    _banner("Single-Round Interactive Protocol  (Section 3.3)")

    # ── Setup ──────────────────────────────────────────────────────────────
    _section("SETUP")
    print(f"  Parameters : n={params.n}, k={params.k}, r={params.r}, m={params.m}")
    print(f"  Field      : GF(2^{params.m})")

    t0 = time.perf_counter()
    inst = generate_instance(params)
    t_gen = time.perf_counter() - t0

    print(f"  H shape    : {params.n - params.k} × {params.n}")
    print(f"  s (syndrome, first 4 elems): {inst.s[:4]} …")
    print(f"  e (error vec, first 4 elems): {inst.e[:4]} …")
    print(f"  rank(e)    : ≤ {params.r}  [guaranteed by decomposition]")
    print(f"  Witness valid: {verify_witness(inst)}")
    print(f"  Instance generation time: {t_gen*1000:.2f} ms")

    # ── Commit ─────────────────────────────────────────────────────────────
    _section("COMMIT  (Prover → Verifier)")
    prover   = Prover(inst)
    verifier = Verifier(inst)

    t0 = time.perf_counter()
    C = prover.commit()
    t_commit = time.perf_counter() - t0

    verifier.receive_commitment(C)
    print(f"  Global commitment C: {C.hex()[:32]}…")
    print(f"  Commit time: {t_commit*1000:.2f} ms")

    # ── Challenge ──────────────────────────────────────────────────────────
    _section("CHALLENGE  (Verifier → Prover)")
    import random
    ch = random.randint(1, 3)
    print(f"  Verifier selects ch = {ch}  (opens P{ch} and P{(ch%3)+1})")
    print(f"  Hidden party: P{((ch+1)%3)+1}")

    # ── Response ───────────────────────────────────────────────────────────
    _section("RESPONSE  (Prover → Verifier)")
    t0 = time.perf_counter()
    rsp = prover.respond(ch)
    t_rsp = time.perf_counter() - t0

    print(f"  seed_ch    : {rsp.seed_ch.hex()[:16]}…")
    print(f"  seed_ch+1  : {rsp.seed_ch1.hex()[:16]}…")
    print(f"  e_ch+1     : {rsp.e_ch1[:4]}…  ({len(rsp.e_ch1)} elements)")
    print(f"  C_ch+2     : {rsp.C_ch2.hex()[:16]}…")
    has_aux = rsp.aux_ch_X is not None or rsp.aux_ch1_X is not None
    print(f"  Contains aux (X₃,y₃): {has_aux}")
    print(f"  Response time: {t_rsp*1000:.2f} ms")

    # ── Verify ─────────────────────────────────────────────────────────────
    _section("VERIFY")
    t0 = time.perf_counter()
    accepted = verifier.verify(rsp)
    t_ver = time.perf_counter() - t0

    status = "✓  ACCEPTED" if accepted else "✗  REJECTED"
    print(f"  Verification result: {status}")
    print(f"  Verify time: {t_ver*1000:.2f} ms")
    print(f"\n  Soundness error (one round): 2/3 ≈ {2/3:.4f}")
    print(f"  For 128-bit security, repeat κ = 219 times.")


def demo_nizk(params_name: str, kappa: int) -> None:
    from mpci_head import generate_instance, prove, verify_proof
    from mpci_head.rsd import RSDParams
    from mpci_head.nizk import proof_size_bytes

    param_map = {
        "tiny":  RSDParams.tiny(),
        "small": RSDParams.small(),
        "paper": RSDParams.paper_128(),
    }
    params = param_map[params_name]

    _banner(f"Non-Interactive ZK Proof  (Section 5)  κ={kappa}")
    print(f"  Parameters: n={params.n}, k={params.k}, r={params.r}, m={params.m}")

    inst = generate_instance(params)

    # Prove
    print(f"\n  Generating proof ({kappa} rounds) …", end="", flush=True)
    t0 = time.perf_counter()
    proof = prove(inst, kappa=kappa)
    t_prove = time.perf_counter() - t0
    print(f"  done  ({t_prove:.3f} s)")

    # Verify
    print("  Verifying proof …", end="", flush=True)
    t0 = time.perf_counter()
    ok = verify_proof(inst, proof, kappa=kappa)
    t_verify = time.perf_counter() - t0
    print(f"  done  ({t_verify:.3f} s)")

    status = "✓  ACCEPTED" if ok else "✗  REJECTED"
    print(f"\n  Result : {status}")

    size_est = proof_size_bytes(params, kappa)
    print(f"  Proof size (estimate): {size_est / 1024:.1f} KB")
    print(f"  Soundness error: (2/3)^{kappa} ≈ 2^{{-{kappa * 0.585:.0f}}}")


def demo_bench(params_name: str, rounds: int) -> None:
    from mpci_head import generate_instance, run_interactive_round
    from mpci_head.rsd import RSDParams

    param_map = {
        "tiny":  RSDParams.tiny(),
        "small": RSDParams.small(),
        "paper": RSDParams.paper_128(),
    }
    params = param_map[params_name]

    _banner(f"Benchmark: {rounds} interactive rounds, params={params_name}")

    inst = generate_instance(params)
    times = []
    for i in range(rounds):
        t0 = time.perf_counter()
        ok = run_interactive_round(inst)
        elapsed = time.perf_counter() - t0
        if not ok:
            print(f"  Round {i}: FAILED (unexpected)")
            sys.exit(1)
        times.append(elapsed)
        if (i + 1) % max(1, rounds // 10) == 0:
            print(f"  Round {i+1:>4}/{rounds}  last={elapsed*1000:.2f} ms")

    avg = sum(times) / len(times)
    mn  = min(times)
    mx  = max(times)
    print(f"\n  Results over {rounds} rounds:")
    print(f"    avg : {avg*1000:.2f} ms")
    print(f"    min : {mn*1000:.2f} ms")
    print(f"    max : {mx*1000:.2f} ms")
    print(f"    all passed: ✓")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MPC-in-the-Head RSD protocol demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["interactive", "nizk", "bench"],
        default="interactive",
        help="Demo mode (default: interactive)",
    )
    parser.add_argument(
        "--params",
        choices=["tiny", "small", "paper"],
        default="small",
        help="Parameter preset (default: small)",
    )
    parser.add_argument(
        "--kappa",
        type=int,
        default=20,
        help="Number of NIZK repetitions (default: 20)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=50,
        help="Number of benchmark rounds (default: 50)",
    )
    args = parser.parse_args()

    if args.mode == "interactive":
        demo_interactive(args.params)
    elif args.mode == "nizk":
        demo_nizk(args.params, args.kappa)
    else:
        demo_bench(args.params, args.rounds)

    print()


if __name__ == "__main__":
    main()
