"""
Finite field arithmetic for MPC-in-the-Head RSD protocol.

Supports:
  - GF(2)  : the base field F_q with q=2
  - GF(2^m): the extension field F_{q^m} represented as binary polynomials
              modulo an irreducible polynomial of degree m.

Elements of GF(2^m) are stored as Python integers whose binary representation
encodes the polynomial coefficients (LSB = constant term).
"""

from __future__ import annotations
import os
import random
from typing import List, Sequence


# ---------------------------------------------------------------------------
# Irreducible polynomials for GF(2^m)
# Each entry is the integer representation of the primitive polynomial,
# NOT including the leading x^m term (which is always 1).
# Source: standard tables for binary extension fields.
# ---------------------------------------------------------------------------
_IRRED_POLYS: dict[int, int] = {
    4:  0b0011,       # x^4 + x + 1
    8:  0b00011011,   # x^8 + x^4 + x^3 + x + 1  (AES field)
    16: 0b101101,     # x^16 + x^5 + x^3 + x^2 + 1
    32: 0b10000111,   # x^32 + x^7 + x^3 + x^2 + 1
    41: (1 << 20) | (1 << 18) | (1 << 2) | 1,   # x^41+x^20+x^18+x^2+1
    64: (1 << 4) | (1 << 3) | (1 << 1) | 1,     # x^64+x^4+x^3+x+1
}


def _get_irred(m: int) -> int:
    if m not in _IRRED_POLYS:
        raise ValueError(
            f"No built-in irreducible polynomial for GF(2^{m}). "
            f"Supported degrees: {sorted(_IRRED_POLYS)}"
        )
    return _IRRED_POLYS[m]


# ---------------------------------------------------------------------------
# GF(2) scalar helpers (trivial but kept explicit for clarity)
# ---------------------------------------------------------------------------

def gf2_add(a: int, b: int) -> int:
    return a ^ b

def gf2_mul(a: int, b: int) -> int:
    return a & b


# ---------------------------------------------------------------------------
# GF(2^m) element arithmetic
# ---------------------------------------------------------------------------

class GF2m:
    """
    Elements of GF(2^m).  All arithmetic is done over the irreducible
    polynomial stored in `self.mod`.
    """

    def __init__(self, m: int) -> None:
        self.m = m
        self.mod = _get_irred(m) | (1 << m)   # include the x^m term
        self.size = 1 << m                     # 2^m elements

    # ------------------------------------------------------------------
    def _reduce(self, a: int) -> int:
        """Reduce a polynomial a modulo the irreducible polynomial."""
        mod = self.mod
        for i in range(a.bit_length() - 1, self.m - 1, -1):
            if (a >> i) & 1:
                a ^= mod << (i - self.m)
        return a

    def add(self, a: int, b: int) -> int:
        return a ^ b

    def sub(self, a: int, b: int) -> int:
        return a ^ b          # same as add in characteristic 2

    def mul(self, a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a >> self.m:
                a ^= self.mod
            b >>= 1
        return result

    def inv(self, a: int) -> int:
        """Multiplicative inverse via extended Euclidean over GF(2)[x]."""
        if a == 0:
            raise ZeroDivisionError("0 has no inverse in GF(2^m)")
        # Using Fermat: a^{2^m - 2}
        return self.pow(a, self.size - 2)

    def pow(self, a: int, exp: int) -> int:
        result = 1
        base = a
        while exp:
            if exp & 1:
                result = self.mul(result, base)
            base = self.mul(base, base)
            exp >>= 1
        return result

    def random_element(self) -> int:
        return int.from_bytes(os.urandom((self.m + 7) // 8), "little") % self.size

    def zero(self) -> int:
        return 0

    def one(self) -> int:
        return 1

    def __repr__(self) -> str:
        return f"GF(2^{self.m})"


# ---------------------------------------------------------------------------
# Vector / matrix arithmetic over GF(2) and GF(2^m)
# ---------------------------------------------------------------------------

def vec_xor(a: List[int], b: List[int]) -> List[int]:
    """Component-wise XOR (= addition in characteristic-2 fields)."""
    assert len(a) == len(b), "Vector length mismatch"
    return [x ^ y for x, y in zip(a, b)]


def mat_xor(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    """Element-wise XOR of two matrices."""
    return [vec_xor(ra, rb) for ra, rb in zip(A, B)]


def mat_vec_gf2(M: List[List[int]], v: List[int]) -> List[int]:
    """Matrix-vector product over GF(2):  w = M * v  (mod 2)."""
    return [
        int(sum(M[i][j] & v[j] for j in range(len(v))) % 2)
        for i in range(len(M))
    ]


def mat_vec_gf2m(field: GF2m, M: List[List[int]], v: List[int]) -> List[int]:
    """
    Matrix-vector product where M is over GF(2^m) and v is over GF(2^m).
    Result is in GF(2^m)^{rows(M)}.
    """
    rows, cols = len(M), len(M[0])
    assert len(v) == cols
    result = []
    for i in range(rows):
        acc = 0
        for j in range(cols):
            acc = field.add(acc, field.mul(M[i][j], v[j]))
        result.append(acc)
    return result


def mixed_mat_vec(field: GF2m, X: List[List[int]], y: List[int]) -> List[int]:
    """
    Mixed-field product:  e = X * y
    X is over GF(2) (base field, i.e. entries are 0 or 1)
    y is over GF(2^m) (extension field)
    Result e is in GF(2^m)^n.

    e_i = sum_j X_{i,j} * y_j   where * is scalar multiplication in GF(2^m).
    Since X_{i,j} in {0,1}, this reduces to:  e_i = XOR of y_j for j where X_{i,j}=1
    """
    n, r = len(X), len(X[0])
    assert len(y) == r
    result = []
    for i in range(n):
        acc = field.zero()
        for j in range(r):
            if X[i][j]:               # GF(2) coefficient = 1
                acc = field.add(acc, y[j])
        result.append(acc)
    return result


def rank_weight(field: GF2m, e: List[int]) -> int:
    """
    Compute rank weight of vector e over GF(2^m):
    = dim_{GF(2)} of the span of {e_1, ..., e_n} as GF(2)-subspace.

    Uses Gaussian elimination on the m x n binary matrix whose columns
    are the binary representations of e_i.
    """
    m = field.m
    n = len(e)
    # Build m x n binary matrix
    rows: List[int] = [0] * m
    for j, ej in enumerate(e):
        for bit in range(m):
            if (ej >> bit) & 1:
                rows[bit] |= (1 << j)
    # Gaussian elimination
    rank = 0
    for col in range(n):
        pivot = None
        for row in range(rank, m):
            if (rows[row] >> col) & 1:
                pivot = row
                break
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for row in range(m):
            if row != rank and (rows[row] >> col) & 1:
                rows[row] ^= rows[rank]
        rank += 1
    return rank


# ---------------------------------------------------------------------------
# Random generation helpers
# ---------------------------------------------------------------------------

def random_vec_gf2(n: int) -> List[int]:
    """Random binary vector of length n."""
    raw = int.from_bytes(os.urandom((n + 7) // 8), "little")
    return [(raw >> i) & 1 for i in range(n)]


def random_mat_gf2(rows: int, cols: int) -> List[List[int]]:
    """Random binary matrix."""
    return [random_vec_gf2(cols) for _ in range(rows)]


def random_vec_gf2m(field: GF2m, n: int) -> List[int]:
    """Random vector in GF(2^m)^n."""
    return [field.random_element() for _ in range(n)]


def random_mat_gf2m(field: GF2m, rows: int, cols: int) -> List[List[int]]:
    """Random matrix in GF(2^m)^{rows x cols}."""
    return [[field.random_element() for _ in range(cols)] for _ in range(rows)]
