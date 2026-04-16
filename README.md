## Limitations and note

- **Pure Python reference implementation. Not optimized for performance. For production environments, consider using a native implementation (C/Rust) with constant time complexity.

- **Constant time cannot be guaranteed. The Python implementation may be vulnerable to time side-channel attacks. Do not use in production systems.

- **Note: This repository provides only a reference implementation of the protocol for research and validation purposes. It is not intended as a benchmark for performance evaluation.

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

## License

MIT License. See [LICENSE](LICENSE).
