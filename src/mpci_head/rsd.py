"""
Rank Syndrome Decoding (RSD) problem instance generation.

Given public parameters (n, k, r, q, m), this module generates:
  - A random parity-check matrix H ∈ GF(q^m)^{(n-k) × n}
  - A secret error vector e ∈ GF(q^m)^n with rank_weight(e) ≤ r
  - The syndrome s = He ∈ GF(q^m)^{n-k}
  - The mixed-field witness (X, y) such that e = X · y,
    where X ∈ GF(q)^{n × r} and y ∈ GF(q^m)^r.

The RSD problem: given (H, s, r), find e such that He = s and rank(e) ≤ r.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple

from .field import (
    GF2m,
    mixed_mat_vec,
    mat_vec_gf2m,
    rank_weight,
    random_mat_gf2,
    random_mat_gf2m,
    random_vec_gf2m,
)


# ---------------------------------------------------------------------------
# Public parameters
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RSDParams:
    """
    Parameters for an RSD instance at 128-bit post-quantum security.

    Default values follow Section 6.1 of the paper:
      n=38, k=19, r=7, q=2, m=41
    which yields a claimed attack complexity of 2^{130.7}.

    For tests and demonstrations we expose a 'small' preset:
      n=8, k=4, r=2, q=2, m=8
    """
    n: int         # code length
    k: int         # information dimension
    r: int         # rank weight bound
    m: int         # extension degree (GF(2^m))
    # q is always 2 in this implementation
    q: int = 2

    @property
    def redundancy(self) -> int:
        return self.n - self.k

    @classmethod
    def paper_128(cls) -> "RSDParams":
        """Parameters from Section 6.1 targeting 128-bit security."""
        return cls(n=38, k=19, r=7, m=41)

    @classmethod
    def small(cls) -> "RSDParams":
        """Small parameters for unit tests and demonstrations."""
        return cls(n=8, k=4, r=2, m=8)

    @classmethod
    def tiny(cls) -> "RSDParams":
        """Minimal parameters (n=4, k=2, r=2, m=4) for debugging."""
        return cls(n=4, k=2, r=2, m=4)


# ---------------------------------------------------------------------------
# Instance / key generation
# ---------------------------------------------------------------------------

@dataclass
class RSDInstance:
    """A complete RSD problem instance with secret witness."""
    params: RSDParams
    field: GF2m
    H: List[List[int]]   # parity-check matrix, (n-k) × n over GF(2^m)
    s: List[int]          # syndrome = He,  (n-k) over GF(2^m)
    e: List[int]          # secret error vector, n over GF(2^m)
    X: List[List[int]]    # coefficient matrix, n × r over GF(2)
    y: List[int]          # basis vector, r over GF(2^m)


def generate_instance(params: RSDParams) -> RSDInstance:
    """
    Generate a fresh RSD instance:

      1. Sample H uniformly at random.
      2. Sample X ∈ GF(2)^{n×r} and y ∈ GF(2^m)^r uniformly at random.
      3. Compute e = X · y  (guarantees rank(e) ≤ r by Lemma 1 in the paper).
      4. Compute s = H · e.

    Returns the full instance including the secret witness (X, y).
    """
    field = GF2m(params.m)
    n, k, r = params.n, params.k, params.r
    nk = n - k   # redundancy

    # Public parity-check matrix H
    H = random_mat_gf2m(field, nk, n)

    # Secret witness
    X = random_mat_gf2(n, r)      # over GF(2)
    y = random_vec_gf2m(field, r) # over GF(2^m)

    # Error vector: e = X * y  (mixed-field product, rank ≤ r guaranteed)
    e = mixed_mat_vec(field, X, y)

    # Syndrome: s = H * e
    s = mat_vec_gf2m(field, H, e)

    return RSDInstance(params=params, field=field, H=H, s=s, e=e, X=X, y=y)


def verify_witness(inst: RSDInstance) -> bool:
    """
    Check that the stored witness (X, y) is valid for (H, s, r):
      1. e = X · y
      2. H · e = s
      3. rank(e) ≤ r
    """
    field = inst.field
    e_check = mixed_mat_vec(field, inst.X, inst.y)
    if e_check != inst.e:
        return False
    s_check = mat_vec_gf2m(field, inst.H, inst.e)
    if s_check != inst.s:
        return False
    rw = rank_weight(field, inst.e)
    if rw > inst.params.r:
        return False
    return True
