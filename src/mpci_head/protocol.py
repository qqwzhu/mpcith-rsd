"""
Single-round interactive MPC-in-the-Head protocol for RSD (Section 3.3).

Protocol overview (3-move Σ-protocol):

  Setup
  ─────
    Public : H ∈ GF(q^m)^{(n-k)×n},  s ∈ GF(q^m)^{n-k},  r ∈ Z⁺
    Secret : X ∈ GF(q)^{n×r},  y ∈ GF(q^m)^r   s.t.  H(Xy) = s

  Commit  (Prover → Verifier)
  ───────────────────────────
    1. Sample seeds seed₁, seed₂, seed₃.
    2. Derive blinding factors  Rᵢ = PRG(seedᵢ) ∈ GF(q^m)^n.
    3. Share X = X₁ ⊕ X₂ ⊕ X₃,  y = y₁ ⊕ y₂ ⊕ y₃.
       (X₁,X₂,y₁,y₂ are PRG-derived; X₃,y₃ are computed.)
    4. Each virtual party Pᵢ computes locally:
         eᵢ = Xᵢyᵢ ⊕ Xᵢyᵢ₊₁ ⊕ Xᵢ₊₁yᵢ ⊕ Rᵢ ⊕ Rᵢ₊₁
         sᵢ = H · eᵢ
         Viewᵢ = (seedᵢ, auxᵢ, eᵢ)
         Cᵢ    = Hash(Viewᵢ)
       where auxᵢ = ∅ for i∈{1,2},  aux₃ = (X₃, y₃).
    5. C = Hash(s₁, s₂, s₃, C₁, C₂, C₃)    ← sent to verifier

  Challenge  (Verifier → Prover)
  ────────────────────────────────
    ch ←$ {1, 2, 3}

  Response  (Prover → Verifier)
  ──────────────────────────────
    Rsp = (seed_ch, seed_{ch+1}, aux_ch, aux_{ch+1}, e_{ch+1}, C_{ch+2})

  Verify
  ──────
    1. Re-derive (X_ch, y_ch, R_ch) and (X_{ch+1}, y_{ch+1}, R_{ch+1}) from seeds.
    2. Re-execute cross-multiplication to get e_ch.
       Read e_{ch+1} from Rsp.
    3. Compute s_ch = H·e_ch,  s_{ch+1} = H·e_{ch+1}.
    4. Derive  s_{ch+2} = s ⊕ s_ch ⊕ s_{ch+1}.
    5. Recompute C_ch and C_{ch+1} from reconstructed views.
       Read C_{ch+2} from Rsp.
    6. Accept iff  Hash(s₁,s₂,s₃,C₁,C₂,C₃) == C  and views are consistent.

Soundness error of one round: 2/3.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .field import (
    GF2m,
    mat_vec_gf2m,
    mixed_mat_vec,
    vec_xor,
    mat_xor,
)
from .hash_utils import (
    H as commit_hash,
    PRG,
    new_seed,
    expand_seed_gf2_mat,
    expand_seed_gf2m,
    serialise,
    HASH_LEN,
)
from .rsd import RSDInstance, RSDParams


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PartyView:
    """Local view of one virtual party."""
    seed: bytes
    aux_X: Optional[List[List[int]]]  # only set for P₃
    aux_y: Optional[List[int]]        # only set for P₃
    e:    List[int]                   # error-vector share (GF(2^m)^n)


@dataclass
class Commitment:
    """Prover's first message."""
    C:  bytes              # global commitment Hash(s₁,s₂,s₃,C₁,C₂,C₃)
    Ci: List[bytes]        # [C₁, C₂, C₃]  – kept by prover, C goes to verifier

    # Prover retains full views for the response phase
    views: List[PartyView]
    si:    List[List[int]] # [s₁, s₂, s₃]


@dataclass
class Response:
    """Prover's third message."""
    ch:         int            # challenge that was answered (1-indexed)
    seed_ch:    bytes
    seed_ch1:   bytes          # seed_{ch+1}
    aux_ch_X:   Optional[List[List[int]]]
    aux_ch_y:   Optional[List[int]]
    aux_ch1_X:  Optional[List[List[int]]]
    aux_ch1_y:  Optional[List[int]]
    e_ch1:      List[int]      # e_{ch+1}  (read from prover's view)
    C_ch2:      bytes          # commitment of the hidden party


# ---------------------------------------------------------------------------
# Helper: modular index with 1-based, mod-3 wrap-around
# ---------------------------------------------------------------------------

def _idx(i: int) -> int:
    """1-based index with wrap-around in {1,2,3}."""
    return ((i - 1) % 3) + 1


def _i0(i: int) -> int:
    """Convert 1-based to 0-based index."""
    return i - 1


# ---------------------------------------------------------------------------
# Core computation shared by Prover and Verifier
# ---------------------------------------------------------------------------

def _cross_mul(
    field: GF2m,
    Xi: List[List[int]], yi: List[int],
    Xj: List[List[int]], yj: List[int],
    Ri: List[int], Rj: List[int],
) -> List[int]:
    """
    Local computation of party Pᵢ's error-vector share:

        eᵢ = Xᵢyᵢ ⊕ Xᵢyⱼ ⊕ Xⱼyᵢ ⊕ Rᵢ ⊕ Rⱼ

    where j = i+1 (mod 3).
    """
    t1 = mixed_mat_vec(field, Xi, yi)
    t2 = mixed_mat_vec(field, Xi, yj)
    t3 = mixed_mat_vec(field, Xj, yi)
    return vec_xor(vec_xor(vec_xor(t1, t2), t3), vec_xor(Ri, Rj))


def _derive_party_shares(
    seed: bytes,
    params: RSDParams,
    aux_X: Optional[List[List[int]]] = None,
    aux_y: Optional[List[int]] = None,
) -> Tuple[List[List[int]], List[int], List[int]]:
    """
    Derive (Xᵢ, yᵢ, Rᵢ) from a seed.

    - If aux_X / aux_y are provided (party 3), use them directly for Xᵢ, yᵢ.
    - Otherwise, expand the seed via PRG.
    - Rᵢ is always PRG-derived.
    """
    n, r, m = params.n, params.r, params.m
    elem_bytes = (m + 7) // 8
    mask = (1 << m) - 1

    # Blinding factor (always PRG-derived)
    R_bytes = PRG(seed + b"\x00", n * elem_bytes)
    Ri = [
        int.from_bytes(R_bytes[j * elem_bytes:(j + 1) * elem_bytes], "little") & mask
        for j in range(n)
    ]

    if aux_X is not None and aux_y is not None:
        Xi, yi = aux_X, aux_y
    else:
        # Expand seed for X share (binary matrix)
        Xi = expand_seed_gf2_mat(seed + b"\x01", n, r)
        # Expand seed for y share
        yi = expand_seed_gf2m(seed + b"\x02", m, r)

    return Xi, yi, Ri


# ---------------------------------------------------------------------------
# Prover
# ---------------------------------------------------------------------------

class Prover:
    """
    Honest prover for the single-round interactive protocol.
    """

    def __init__(self, inst: RSDInstance) -> None:
        self.inst = inst
        self._comm: Optional[Commitment] = None

    # ------------------------------------------------------------------
    def commit(self) -> bytes:
        """
        Execute the commit phase.
        Returns the global commitment C to send to the verifier.
        """
        inst = self.inst
        field = inst.field
        p = inst.params
        n, r, m = p.n, p.r, p.m

        # Step 1: Sample three seeds
        seeds = [new_seed(), new_seed(), new_seed()]

        # Step 2: Derive blinding factors and shares for P₁, P₂ via PRG
        X1, y1, R1 = _derive_party_shares(seeds[0], p)
        X2, y2, R2 = _derive_party_shares(seeds[1], p)

        # Step 3: Compute X₃ = X ⊕ X₁ ⊕ X₂,  y₃ = y ⊕ y₁ ⊕ y₂
        X3 = mat_xor(mat_xor(inst.X, X1), X2)
        y3 = vec_xor(vec_xor(inst.y, y1), y2)

        # Blinding factor for P₃ is still PRG-derived from seed₃
        _, _, R3 = _derive_party_shares(seeds[2], p, aux_X=X3, aux_y=y3)

        # Step 4: Each party computes its error share and syndrome share
        shares_X = [X1, X2, X3]
        shares_y = [y1, y2, y3]
        blinding  = [R1, R2, R3]

        e_shares: List[List[int]] = []
        s_shares: List[List[int]] = []
        for i in range(3):          # 0-indexed internally
            j = (i + 1) % 3
            ei = _cross_mul(
                field,
                shares_X[i], shares_y[i],
                shares_X[j], shares_y[j],
                blinding[i], blinding[j],
            )
            si = mat_vec_gf2m(field, inst.H, ei)
            e_shares.append(ei)
            s_shares.append(si)

        # Step 4 cont: Build views and per-party commitments
        views: List[PartyView] = []
        Ci_list: List[bytes] = []
        for i in range(3):
            aux_X_i = X3 if i == 2 else None
            aux_y_i = y3 if i == 2 else None
            view = PartyView(
                seed=seeds[i],
                aux_X=aux_X_i,
                aux_y=aux_y_i,
                e=e_shares[i],
            )
            # Ci = Hash(seedᵢ, auxᵢ, eᵢ)
            ci = commit_hash(
                seeds[i],
                serialise(X3, elem_bytes=1) + serialise(y3) if i == 2 else b"",
                e_shares[i],
            )
            views.append(view)
            Ci_list.append(ci)

        # Global commitment C = Hash(s₁,s₂,s₃,C₁,C₂,C₃)
        C = commit_hash(
            s_shares[0], s_shares[1], s_shares[2],
            Ci_list[0], Ci_list[1], Ci_list[2],
        )

        self._comm = Commitment(C=C, Ci=Ci_list, views=views, si=s_shares)
        return C

    # ------------------------------------------------------------------
    def respond(self, ch: int) -> Response:
        """
        Execute the response phase given verifier's challenge ch ∈ {1,2,3}.
        """
        if self._comm is None:
            raise RuntimeError("Must call commit() before respond()")
        if ch not in (1, 2, 3):
            raise ValueError(f"Invalid challenge {ch}")

        comm = self._comm
        i0  = _i0(ch)             # 0-based index of party ch
        i10 = _i0(_idx(ch + 1))   # 0-based index of party ch+1
        i20 = _i0(_idx(ch + 2))   # 0-based index of party ch+2 (hidden)

        vch  = comm.views[i0]
        vch1 = comm.views[i10]

        return Response(
            ch=ch,
            seed_ch=vch.seed,
            seed_ch1=vch1.seed,
            aux_ch_X=vch.aux_X,
            aux_ch_y=vch.aux_y,
            aux_ch1_X=vch1.aux_X,
            aux_ch1_y=vch1.aux_y,
            e_ch1=vch1.e,
            C_ch2=comm.Ci[i20],
        )


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class Verifier:
    """
    Honest verifier for the single-round interactive protocol.
    """

    def __init__(self, inst: RSDInstance) -> None:
        """
        In a real deployment the verifier only knows (H, s, r).
        We accept the full instance but only use public fields.
        """
        self.H  = inst.H
        self.s  = inst.s
        self.params = inst.params
        self.field  = inst.field
        self._C: Optional[bytes] = None

    # ------------------------------------------------------------------
    def receive_commitment(self, C: bytes) -> None:
        """Store the prover's first message."""
        self._C = C

    # ------------------------------------------------------------------
    def verify(self, rsp: Response) -> bool:
        """
        Execute the verification phase.
        Returns True iff the proof is accepted.
        """
        if self._C is None:
            raise RuntimeError("Must call receive_commitment() before verify()")

        p      = self.params
        field  = self.field
        ch     = rsp.ch
        ch1    = _idx(ch + 1)
        ch2    = _idx(ch + 2)

        # Step 1: Re-derive shares and blinding factors for parties ch, ch+1
        Xch, ych, Rch = _derive_party_shares(
            rsp.seed_ch, p, rsp.aux_ch_X, rsp.aux_ch_y
        )
        Xch1, ych1, Rch1 = _derive_party_shares(
            rsp.seed_ch1, p, rsp.aux_ch1_X, rsp.aux_ch1_y
        )

        # Step 2: Re-execute cross-multiplication to obtain e_ch
        e_ch = _cross_mul(field, Xch, ych, Xch1, ych1, Rch, Rch1)

        # Read e_{ch+1} from the response
        e_ch1 = rsp.e_ch1

        # Step 3: Compute syndrome shares for the two opened parties
        s_ch  = mat_vec_gf2m(field, self.H, e_ch)
        s_ch1 = mat_vec_gf2m(field, self.H, e_ch1)

        # Step 4: Algebraically derive the hidden syndrome share
        # s_{ch+2} = s ⊕ s_ch ⊕ s_{ch+1}
        s_ch2 = vec_xor(vec_xor(self.s, s_ch), s_ch1)

        # Step 5: Recompute per-party commitments
        def party_commit(seed, aux_X, aux_y, e):
            aux_bytes = (
                serialise(aux_X, elem_bytes=1) + serialise(aux_y)
                if aux_X is not None else b""
            )
            return commit_hash(seed, aux_bytes, e)

        C_ch_re  = party_commit(rsp.seed_ch,  rsp.aux_ch_X,  rsp.aux_ch_y,  e_ch)
        C_ch1_re = party_commit(rsp.seed_ch1, rsp.aux_ch1_X, rsp.aux_ch1_y, e_ch1)
        C_ch2_rsp = rsp.C_ch2     # taken from response (hidden party)

        # Re-order into [C₁, C₂, C₃] and [s₁, s₂, s₃]
        s_map: dict[int, List[int]] = {ch: s_ch, ch1: s_ch1, ch2: s_ch2}
        C_map: dict[int, bytes]     = {ch: C_ch_re, ch1: C_ch1_re, ch2: C_ch2_rsp}

        s1, s2, s3 = s_map[1], s_map[2], s_map[3]
        C1, C2, C3 = C_map[1], C_map[2], C_map[3]

        # Step 6: Recompute global commitment and compare
        C_prime = commit_hash(s1, s2, s3, C1, C2, C3)
        return C_prime == self._C


# ---------------------------------------------------------------------------
# Convenience: run one complete interactive round
# ---------------------------------------------------------------------------

def run_interactive_round(inst: RSDInstance, ch: Optional[int] = None) -> bool:
    """
    Execute one full round of the single-round interactive protocol.

    Parameters
    ----------
    inst : RSDInstance
        A valid RSD instance including the secret witness.
    ch : int or None
        Challenge value in {1,2,3}. If None, chosen uniformly at random.

    Returns
    -------
    bool
        True iff the verifier accepts.
    """
    import random as _rng
    if ch is None:
        ch = _rng.randint(1, 3)

    prover   = Prover(inst)
    verifier = Verifier(inst)

    # Commit
    C = prover.commit()
    verifier.receive_commitment(C)

    # Challenge
    # (ch is supplied externally; in a real protocol the verifier picks it)

    # Response
    rsp = prover.respond(ch)

    # Verify
    return verifier.verify(rsp)
