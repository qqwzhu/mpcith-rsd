# Limitations and note

Pure Python reference implementation. Not optimized for performance. For production environments, consider using a native implementation (C/Rust) with constant time complexity.

Constant time cannot be guaranteed. The Python implementation may be vulnerable to time side-channel attacks. Do not use in production systems.

Note: This repository provides only a reference implementation of the protocol for research and validation purposes. It is not intended as a benchmark for performance evaluation.

# MPC-in-the-Head ZK Proof for Rank Syndrome Decoding

A pure-Python implementation of the zero-knowledge proof scheme described in:

> **MPC-in-the-Head Zero-Knowledge Proof for Rank Syndrome Decoding via Mixed-Field Secret Sharing**

The scheme constructs a ZK proof of knowledge for the **Rank Syndrome Decoding (RSD)** problem using the **MPC-in-the-Head (MPCitH)** paradigm with a (2,3)-secret-sharing mechanism over mixed fields GF(2) and GF(2^m).

---

## Overview

### What is proved?

Given a public parity-check matrix `H ∈ GF(2^m)^{(n-k)×n}` and syndrome `s ∈ GF(2^m)^{n-k}`, the prover demonstrates knowledge of a secret error vector `e ∈ GF(2^m)^n` such that:

```
H · e = s   and   rank_{GF(2)}(e) ≤ r
```

without revealing `e`.

### Core technique

The rank constraint is handled by decomposing `e` as a **mixed-field matrix product**:

```
e = X · y
```

where `X ∈ GF(2)^{n×r}` (base field) and `y ∈ GF(2^m)^r` (extension field).  By **Lemma 1** in the paper, this decomposition implicitly enforces `rank(e) ≤ r`.

The product `X · y` is then computed inside a **(2,3)-secret sharing** MPC-in-the-Head protocol, with each virtual party computing its local cross-term:

```
e_i = X_i y_i ⊕ X_i y_{i+1} ⊕ X_{i+1} y_i ⊕ R_i ⊕ R_{i+1}
```

The blinding factors `R_i` cancel cyclically (`R_1⊕R_2 ⊕ R_2⊕R_3 ⊕ R_3⊕R_1 = 0`), ensuring completeness.

---

## Repository structure

```
.
├── src/
│   └── mpci_head/
│       ├── __init__.py       # Public API
│       ├── field.py          # GF(2) / GF(2^m) arithmetic, rank weight
│       ├── hash_utils.py     # SHA3-256, PRG, KDF, commitment
│       ├── rsd.py            # RSD instance / witness generation
│       ├── protocol.py       # Single-round interactive Σ-protocol (§3.3)
│       └── nizk.py           # Non-interactive proof via Fiat-Shamir (§5)
├── tests/
│   ├── test_field.py         # GF(2^m) arithmetic tests
│   ├── test_protocol.py      # Completeness + soundness sanity tests
│   └── test_nizk.py          # NIZK completeness + integrity tests
├── demo.py                   # Command-line demonstration
├── pyproject.toml
└── README.md
```

---

## Installation

Requires **Python ≥ 3.10**. No third-party dependencies.

```bash
git clone https://github.com/your-org/mpci-head-rsd.git
cd mpci-head-rsd
pip install -e ".[dev]"
```

---

## Quick start

### Interactive protocol (one round)

```python
from mpci_head import generate_instance, run_interactive_round
from mpci_head.rsd import RSDParams

# Small parameters for fast experimentation
params = RSDParams.small()          # n=8, k=4, r=2, m=8
inst   = generate_instance(params)

accepted = run_interactive_round(inst)
print("Accepted:", accepted)        # True (honest prover)
```

### Step-by-step interactive protocol

```python
from mpci_head import generate_instance, Prover, Verifier
from mpci_head.rsd import RSDParams
import random

params = RSDParams.small()
inst   = generate_instance(params)

prover   = Prover(inst)
verifier = Verifier(inst)

# 1. Commit
C  = prover.commit()
verifier.receive_commitment(C)

# 2. Challenge
ch = random.randint(1, 3)

# 3. Response + Verify
rsp      = prover.respond(ch)
accepted = verifier.verify(rsp)
print(f"ch={ch}  accepted={accepted}")
```

### Non-interactive proof (Fiat-Shamir)

```python
from mpci_head import generate_instance, prove, verify_proof
from mpci_head.rsd import RSDParams
from mpci_head.nizk import recommended_kappa

params = RSDParams.small()
inst   = generate_instance(params)

kappa = 20          # use recommended_kappa(128) = 219 for real security
proof = prove(inst, kappa=kappa)
ok    = verify_proof(inst, proof, kappa=kappa)
print("Valid proof:", ok)
```

---

## Demo script

```bash
# Interactive round, tiny parameters
python demo.py --mode interactive --params tiny

# NIZK proof, small parameters, κ=30 rounds
python demo.py --mode nizk --params small --kappa 30

# Benchmark 100 interactive rounds
python demo.py --mode bench --params small --rounds 100
```

---

## Running tests

```bash
pytest                    # all tests
pytest tests/test_field.py -v
pytest --tb=short -q      # quiet mode
```

---

## Security parameters

| Preset   | n  | k  | r | m  | Attack complexity |
|----------|----|----|---|----|-------------------|
| `tiny`   | 4  | 2  | 2 | 4  | toy (not secure)  |
| `small`  | 8  | 4  | 2 | 8  | toy (not secure)  |
| `paper`  | 38 | 19 | 7 | 41 | ≥ 2^{130.7}       |

For **128-bit post-quantum security**, use `RSDParams.paper_128()` with `κ = recommended_kappa(128) = 219`.

Expected proof size at 128-bit security: **≈ 65.2 KB** (Equation 7 in the paper).

---

## Protocol security properties

| Property | Guarantee |
|---|---|
| **Completeness** | Honest prover always accepted (Theorem 1) |
| **3-Special Soundness** | Any cheating prover succeeds with prob. ≤ 2/3 per round (Theorem 2) |
| **SHVZK** | Polynomial-time simulator exists; witness not leaked (Theorem 3) |
| **NIZK (ROM)** | Fiat-Shamir in Random Oracle Model gives computational soundness |

---

## Limitations and notes

- **Pure-Python reference implementation.** Not optimised for performance. For production use, consider a native implementation (C/Rust) with constant-time operations.
- **Constant-time not guaranteed.** The Python implementation may be vulnerable to timing side-channels. Do not use in production systems.
- **GF(2^m) arithmetic** is implemented via schoolbook polynomial multiplication with a fixed irreducible polynomial. Supported degrees: 4, 8, 16, 32, 41, 64.
- The hash function is **SHA3-256** (Python `hashlib.sha3_256`).

---

## License

MIT License. See [LICENSE](LICENSE).
