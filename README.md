## Limitations and note

- **Pure Python reference implementation. Not optimized for performance. For production environments, consider using a native implementation (C/Rust) with constant time complexity.

- **Constant time cannot be guaranteed. The Python implementation may be vulnerable to time side-channel attacks. Do not use in production systems.

- **Note: This repository provides only a reference implementation of the protocol for research and validation purposes. It is not intended as a benchmark for performance evaluation.

# MPC-in-the-Head ZK Proof for Rank Syndrome Decoding

A pure-Python implementation of the zero-knowledge proof scheme described in:

> **MPC-in-the-Head Zero-Knowledge Proof for Rank Syndrome Decoding via Mixed-Field Secret Sharing**

The scheme constructs a ZK proof of knowledge for the **Rank Syndrome Decoding (RSD)** problem using the **MPC-in-the-Head (MPCitH)** paradigm with a (2,3)-secret-sharing mechanism over mixed fields GF(2) and GF(2^m).

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
