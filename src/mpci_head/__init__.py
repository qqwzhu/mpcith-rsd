"""
mpci_head_rsd
=============

MPC-in-the-Head Zero-Knowledge Proof for Rank Syndrome Decoding
via Mixed-Field Secret Sharing.

Implementation of the protocol described in:
  "MPC-in-the-Head Zero-Knowledge Proof for Rank Syndrome Decoding
   via Mixed-Field Secret Sharing"

Modules
-------
field        – GF(2) / GF(2^m) arithmetic, rank weight
hash_utils   – SHA3-256 based hash / PRG / KDF / commitment
rsd          – RSD problem instance generation
protocol     – Single-round interactive Σ-protocol (Section 3.3)
nizk         – Non-interactive extension via Fiat-Shamir (Section 5)
"""

from .field import GF2m, rank_weight, mixed_mat_vec
from .rsd import RSDParams, RSDInstance, generate_instance, verify_witness
from .protocol import Prover, Verifier, run_interactive_round
from .nizk import prove, verify_proof, recommended_kappa, proof_size_bytes, NIZKProof

__all__ = [
    "GF2m",
    "rank_weight",
    "mixed_mat_vec",
    "RSDParams",
    "RSDInstance",
    "generate_instance",
    "verify_witness",
    "Prover",
    "Verifier",
    "run_interactive_round",
    "prove",
    "verify_proof",
    "recommended_kappa",
    "proof_size_bytes",
    "NIZKProof",
]

__version__ = "0.1.0"
