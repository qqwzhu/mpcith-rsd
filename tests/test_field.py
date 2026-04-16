"""Tests for GF(2) and GF(2^m) arithmetic."""

import pytest
from mpci_head.field import (
    GF2m,
    vec_xor,
    mat_xor,
    mat_vec_gf2,
    mixed_mat_vec,
    rank_weight,
    random_vec_gf2,
    random_mat_gf2,
    random_vec_gf2m,
)


# ---------------------------------------------------------------------------
# GF(2^m) arithmetic
# ---------------------------------------------------------------------------

class TestGF2m:
    def setup_method(self):
        self.f4  = GF2m(4)
        self.f8  = GF2m(8)
        self.f16 = GF2m(16)

    def test_add_commutative(self):
        f = self.f8
        a, b = f.random_element(), f.random_element()
        assert f.add(a, b) == f.add(b, a)

    def test_add_identity(self):
        f = self.f8
        for _ in range(20):
            a = f.random_element()
            assert f.add(a, 0) == a

    def test_add_self_zero(self):
        f = self.f8
        for _ in range(20):
            a = f.random_element()
            assert f.add(a, a) == 0

    def test_mul_commutative(self):
        f = self.f8
        a, b = f.random_element(), f.random_element()
        assert f.mul(a, b) == f.mul(b, a)

    def test_mul_identity(self):
        f = self.f8
        for _ in range(20):
            a = f.random_element()
            assert f.mul(a, 1) == a

    def test_mul_zero(self):
        f = self.f8
        for _ in range(20):
            a = f.random_element()
            assert f.mul(a, 0) == 0

    def test_mul_associative(self):
        f = self.f8
        a, b, c = f.random_element(), f.random_element(), f.random_element()
        assert f.mul(f.mul(a, b), c) == f.mul(a, f.mul(b, c))

    def test_distributive(self):
        f = self.f8
        a, b, c = f.random_element(), f.random_element(), f.random_element()
        assert f.mul(a, f.add(b, c)) == f.add(f.mul(a, b), f.mul(a, c))

    def test_inverse(self):
        f = self.f8
        for _ in range(20):
            a = f.random_element()
            if a == 0:
                continue
            assert f.mul(a, f.inv(a)) == 1

    def test_inv_zero_raises(self):
        with pytest.raises(ZeroDivisionError):
            self.f8.inv(0)

    def test_pow(self):
        f = self.f8
        a = f.random_element()
        # a^3 == a * a * a
        expected = f.mul(f.mul(a, a), a)
        assert f.pow(a, 3) == expected

    def test_size(self):
        assert GF2m(4).size == 16
        assert GF2m(8).size == 256

    @pytest.mark.parametrize("m", [4, 8, 16])
    def test_all_elements_invertible(self, m):
        f = GF2m(m)
        for a in range(1, min(f.size, 64)):   # sample first 63 non-zero elements
            assert f.mul(a, f.inv(a)) == 1


# ---------------------------------------------------------------------------
# Vector / matrix helpers
# ---------------------------------------------------------------------------

class TestVecMatOps:
    def test_vec_xor_identity(self):
        v = [1, 0, 1, 1, 0]
        assert vec_xor(v, [0] * 5) == v

    def test_vec_xor_self(self):
        v = [1, 0, 1, 1]
        assert vec_xor(v, v) == [0, 0, 0, 0]

    def test_mat_vec_gf2(self):
        M = [[1, 0, 1], [0, 1, 1]]
        v = [1, 1, 0]
        # Row 0: 1*1 ^ 0*1 ^ 1*0 = 1
        # Row 1: 0*1 ^ 1*1 ^ 1*0 = 1
        assert mat_vec_gf2(M, v) == [1, 1]

    def test_mat_vec_gf2_zero(self):
        M = [[1, 0], [0, 1]]
        assert mat_vec_gf2(M, [0, 0]) == [0, 0]


# ---------------------------------------------------------------------------
# Mixed-field product and rank weight
# ---------------------------------------------------------------------------

class TestMixedField:
    def setup_method(self):
        self.field = GF2m(8)

    def test_e_xmy_rank_le_r(self):
        """e = X*y must have rank ≤ r (Lemma 1)."""
        f = self.field
        n, r = 8, 3
        for _ in range(10):
            X = random_mat_gf2(n, r)
            y = random_vec_gf2m(f, r)
            e = mixed_mat_vec(f, X, y)
            assert rank_weight(f, e) <= r, "Rank constraint violated"

    def test_zero_X_gives_zero_e(self):
        f = self.field
        X = [[0] * 4 for _ in range(6)]
        y = random_vec_gf2m(f, 4)
        e = mixed_mat_vec(f, X, y)
        assert all(ei == 0 for ei in e)

    def test_identity_X(self):
        """X = [I_r | 0^{n-r}] gives e = [y | 0 ... 0]."""
        f = self.field
        r, n = 3, 5
        X = [[1 if i == j else 0 for j in range(r)] for i in range(r)]
        X += [[0] * r for _ in range(n - r)]
        y = random_vec_gf2m(f, r)
        e = mixed_mat_vec(f, X, y)
        assert e[:r] == y
        assert all(ei == 0 for ei in e[r:])

    def test_rank_weight_zero_vector(self):
        f = self.field
        assert rank_weight(f, [0, 0, 0]) == 0

    def test_rank_weight_single_nonzero(self):
        f = self.field
        e = [0, 5, 0, 0]
        assert rank_weight(f, e) == 1
