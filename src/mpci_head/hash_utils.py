"""
Commitment and hashing utilities for the MPC-in-the-Head protocol.

We use SHA3-256 as the hash function and a simple counter-based KDF
(also SHA3-256 based) for expanding a master challenge into κ per-round
challenges.

All internal data (vectors, matrices, integers) are serialised to bytes
before hashing so that the hash domain is unambiguous.
"""

from __future__ import annotations
import hashlib
import os
import struct
from typing import Any, List, Sequence


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _int_to_bytes(x: int, length: int = 4) -> bytes:
    """
    Encode a non-negative integer as big-endian bytes.
    Automatically uses more bytes if x doesn't fit in `length` bytes,
    ensuring GF(2^m) elements with large m (e.g. m=41) never overflow.
    """
    needed = max(length, (x.bit_length() + 7) // 8) if x > 0 else length
    return x.to_bytes(needed, "big")


def _list_to_bytes(v: List[int], elem_bytes: int = 4) -> bytes:
    """Serialise a list of integers, each padded to at least elem_bytes."""
    return b"".join(_int_to_bytes(x, elem_bytes) for x in v)


def _mat_to_bytes(M: List[List[int]], elem_bytes: int = 4) -> bytes:
    """Serialise a 2-D list of integers (row-major)."""
    return b"".join(_list_to_bytes(row, elem_bytes) for row in M)


def serialise(*parts: Any, elem_bytes: int = 4) -> bytes:
    """
    Serialise an ordered sequence of objects into bytes.

    Supported types:
      int            → fixed-width big-endian (auto-extended for large values)
      List[int]      → concatenated fixed-width big-endian
      List[List[int]]→ row-major concatenated fixed-width big-endian
      bytes / None   → passed through (None → b"")
    """
    out = bytearray()
    out += struct.pack(">I", len(parts))   # number of parts, for domain separation
    for p in parts:
        if p is None:
            out += b"\x00" * elem_bytes
        elif isinstance(p, (bytes, bytearray)):
            out += struct.pack(">I", len(p))
            out += p
        elif isinstance(p, int):
            out += _int_to_bytes(p, elem_bytes)
        elif isinstance(p, list):
            if len(p) == 0:
                out += struct.pack(">I", 0)
            elif isinstance(p[0], list):
                flat = _mat_to_bytes(p, elem_bytes)
                out += struct.pack(">I", len(flat))
                out += flat
            else:
                flat = _list_to_bytes(p, elem_bytes)
                out += struct.pack(">I", len(flat))
                out += flat
        else:
            raise TypeError(f"Cannot serialise type {type(p)}")
    return bytes(out)


# ---------------------------------------------------------------------------
# Hash / commitment
# ---------------------------------------------------------------------------

HASH_LEN = 32   # SHA3-256 → 32 bytes = 256 bits


def H(*parts: Any, elem_bytes: int = 6) -> bytes:
    """
    Commitment hash function.
    H(v₁, v₂, ...) → 32-byte digest (SHA3-256).

    elem_bytes defaults to 6 to safely cover GF(2^41) elements
    (41 bits → 6 bytes), while also fitting GF(2^8) and smaller fields.
    """
    data = serialise(*parts, elem_bytes=elem_bytes)
    return hashlib.sha3_256(data).digest()


def PRG(seed: bytes, output_len_bytes: int) -> bytes:
    """
    Deterministic pseudorandom generator based on SHA3-256 in counter mode.
    PRG(seed) → `output_len_bytes` pseudo-random bytes.
    """
    out = bytearray()
    ctr = 0
    while len(out) < output_len_bytes:
        block = hashlib.sha3_256(seed + struct.pack(">I", ctr)).digest()
        out += block
        ctr += 1
    return bytes(out[:output_len_bytes])


def KDF(master: bytes, num_challenges: int, challenge_domain: int = 3) -> List[int]:
    """
    Key derivation function: expand master secret into `num_challenges`
    values in {1, ..., challenge_domain}.

    Uses rejection sampling per block to avoid bias.
    """
    challenges: List[int] = []
    ctr = 0
    while len(challenges) < num_challenges:
        block = hashlib.sha3_256(master + struct.pack(">I", ctr)).digest()
        for byte in block:
            max_valid = 256 - (256 % challenge_domain)
            if byte < max_valid:
                challenges.append((byte % challenge_domain) + 1)
            if len(challenges) == num_challenges:
                break
        ctr += 1
    return challenges


def new_seed() -> bytes:
    """Generate a fresh random 32-byte seed."""
    return os.urandom(32)


def expand_seed_gf2(seed: bytes, n: int) -> List[int]:
    """Expand seed → random binary vector of length n."""
    needed = (n + 7) // 8
    raw = PRG(seed, needed)
    raw_int = int.from_bytes(raw, "little")
    return [(raw_int >> i) & 1 for i in range(n)]


def expand_seed_gf2_mat(seed: bytes, rows: int, cols: int) -> List[List[int]]:
    """Expand seed → random binary matrix of shape (rows, cols)."""
    needed = (rows * cols + 7) // 8
    raw = PRG(seed, needed)
    raw_int = int.from_bytes(raw, "little")
    flat = [(raw_int >> i) & 1 for i in range(rows * cols)]
    return [flat[i * cols:(i + 1) * cols] for i in range(rows)]


def expand_seed_gf2m(seed: bytes, field_m: int, n: int) -> List[int]:
    """Expand seed → random vector in GF(2^m)^n."""
    elem_bytes = (field_m + 7) // 8
    raw = PRG(seed, elem_bytes * n)
    mask = (1 << field_m) - 1
    return [
        int.from_bytes(raw[i * elem_bytes:(i + 1) * elem_bytes], "little") & mask
        for i in range(n)
    ]


def expand_seed_gf2m_mat(seed: bytes, field_m: int, rows: int, cols: int) -> List[List[int]]:
    """Expand seed → random matrix in GF(2^m)^{rows x cols}."""
    flat = expand_seed_gf2m(seed, field_m, rows * cols)
    return [flat[i * cols:(i + 1) * cols] for i in range(rows)]