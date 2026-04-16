"""
Non-interactive zero-knowledge proof via Fiat-Shamir (Section 5).

The single-round interactive Σ-protocol from Section 3.3 is turned into a
non-interactive proof by replacing the verifier's random challenge with a
hash of the public input and all commitments:

    CH = Hash(H, s, C⁽¹⁾, …, C⁽ᵏ⁾)
    (ch⁽¹⁾, …, ch⁽ᵏ⁾) = KDF(CH)

The proof is  Π = (CH, Rsp⁽¹⁾, …, Rsp⁽ᵏ⁾).

Security parameters (Section 6.1, 128-bit target):
    κ = ⌈128 / log₂(3/2)⌉ = 219

    Soundness error per round: 2/3
    Total soundness error:     (2/3)^κ ≤ 2^{-128}
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import List, Optional

from .field import GF2m, mat_vec_gf2m, vec_xor
from .hash_utils import (
    H as commit_hash,
    KDF,
    HASH_LEN,
    new_seed,
    serialise,
)
from .rsd import RSDInstance, RSDParams
from .protocol import (
    Prover,
    Verifier,
    Response,
    _idx,
    _i0,
    _derive_party_shares,
    _cross_mul,
)


# ---------------------------------------------------------------------------
# Recommended repetition count
# ---------------------------------------------------------------------------

def recommended_kappa(security_bits: int = 128) -> int:
    """κ = ⌈λ / log₂(3/2)⌉."""
    return math.ceil(security_bits / math.log2(3 / 2))


# ---------------------------------------------------------------------------
# Proof data structure
# ---------------------------------------------------------------------------

@dataclass
class NIZKProof:
    """
    Non-interactive zero-knowledge proof.

    Π = (CH, Rsp⁽¹⁾, …, Rsp⁽ᵏ⁾)
    """
    CH:  bytes              # global challenge hash (= 2λ bits)
    responses: List[Response]  # κ responses


# ---------------------------------------------------------------------------
# Proof size estimate
# ---------------------------------------------------------------------------

def proof_size_bytes(params: RSDParams, kappa: int) -> int:
    """
    Theoretical proof size in bytes (Equation 7 in the paper).

    |Π| = 2λ + κ · (4λ + n·m·ceil(log₂q)/8 + (2/3)·r·(n+m)·ceil(log₂q)/8)

    For q=2, log₂q = 1, so each GF(2^m) element = m bits.
    We round element sizes up to whole bytes.
    """
    lam   = 128            # security parameter bits
    n, r, m = params.n, params.r, params.m
    seed_bytes  = 2 * lam // 8         # 2 seeds × λ bits each
    commit_bytes = 2 * lam // 8        # one unopened commitment
    e_share_bytes = n * m // 8 + (1 if (n * m) % 8 else 0)
    aux_bytes_exp = (2 / 3) * r * (n + m) // 8   # expected aux (2/3 of rounds)

    per_round = seed_bytes + commit_bytes + e_share_bytes + aux_bytes_exp
    total = 2 * lam // 8 + kappa * per_round
    return int(total)


# ---------------------------------------------------------------------------
# Prove
# ---------------------------------------------------------------------------

def prove(inst: RSDInstance, kappa: Optional[int] = None) -> NIZKProof:
    """
    Generate a non-interactive ZK proof for the RSD instance.

    Parameters
    ----------
    inst   : RSDInstance with secret witness (X, y).
    kappa  : Number of repetitions.  Defaults to recommended_kappa(128).

    Returns
    -------
    NIZKProof
    """
    if kappa is None:
        kappa = recommended_kappa()

    p     = inst.params
    field = inst.field

    # ---- Commit phase: run κ independent rounds ----
    provers = [Prover(inst) for _ in range(kappa)]
    round_Cs: List[bytes] = []
    for prv in provers:
        C_j = prv.commit()
        round_Cs.append(C_j)

    # ---- Derive challenge ----
    # CH = Hash(H, s, C⁽¹⁾, …, C⁽ᵏ⁾)
    CH = commit_hash(inst.H, inst.s, *round_Cs)
    challenges: List[int] = KDF(CH, kappa, challenge_domain=3)

    # ---- Response phase ----
    responses: List[Response] = []
    for j, (prv, ch) in enumerate(zip(provers, challenges)):
        rsp = prv.respond(ch)
        responses.append(rsp)

    return NIZKProof(CH=CH, responses=responses)


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_proof(
    inst: RSDInstance,
    proof: NIZKProof,
    kappa: Optional[int] = None,
) -> bool:
    """
    Verify a non-interactive ZK proof.

    Parameters
    ----------
    inst  : RSDInstance – only public fields (H, s, params) are used.
    proof : NIZKProof produced by prove().
    kappa : Expected number of repetitions.

    Returns
    -------
    bool : True iff the proof is valid.
    """
    if kappa is None:
        kappa = recommended_kappa()

    if len(proof.responses) != kappa:
        return False

    p     = inst.params
    field = inst.field

    # ---- Per-round verification ----
    round_Cs_prime: List[bytes] = []
    for rsp in proof.responses:
        ch  = rsp.ch
        ch1 = _idx(ch + 1)
        ch2 = _idx(ch + 2)

        # Re-derive shares
        Xch,  ych,  Rch  = _derive_party_shares(rsp.seed_ch,  p, rsp.aux_ch_X,  rsp.aux_ch_y)
        Xch1, ych1, Rch1 = _derive_party_shares(rsp.seed_ch1, p, rsp.aux_ch1_X, rsp.aux_ch1_y)

        # Re-execute cross-multiplication
        e_ch  = _cross_mul(field, Xch, ych, Xch1, ych1, Rch, Rch1)
        e_ch1 = rsp.e_ch1

        # Syndrome shares
        s_ch  = mat_vec_gf2m(field, inst.H, e_ch)
        s_ch1 = mat_vec_gf2m(field, inst.H, e_ch1)
        s_ch2 = vec_xor(vec_xor(inst.s, s_ch), s_ch1)

        # Per-party commitments
        def _party_commit(seed, aux_X, aux_y, e):
            aux_bytes = (
                serialise(aux_X, elem_bytes=1) + serialise(aux_y)
                if aux_X is not None else b""
            )
            return commit_hash(seed, aux_bytes, e)

        C_ch_re  = _party_commit(rsp.seed_ch,  rsp.aux_ch_X,  rsp.aux_ch_y,  e_ch)
        C_ch1_re = _party_commit(rsp.seed_ch1, rsp.aux_ch1_X, rsp.aux_ch1_y, e_ch1)
        C_ch2_rsp = rsp.C_ch2

        s_map = {ch: s_ch, ch1: s_ch1, ch2: s_ch2}
        C_map = {ch: C_ch_re, ch1: C_ch1_re, ch2: C_ch2_rsp}

        s1, s2, s3 = s_map[1], s_map[2], s_map[3]
        C1, C2, C3 = C_map[1], C_map[2], C_map[3]

        C_j_prime = commit_hash(s1, s2, s3, C1, C2, C3)
        round_Cs_prime.append(C_j_prime)

    # ---- Recompute global challenge and compare ----
    CH_prime = commit_hash(inst.H, inst.s, *round_Cs_prime)
    return CH_prime == proof.CH
