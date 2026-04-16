"""
Tests for the non-interactive ZK proof (Section 5, Fiat-Shamir transform).
"""

import pytest
import copy
import os
from mpci_head.rsd import generate_instance, RSDParams
from mpci_head.nizk import prove, verify_proof, recommended_kappa, proof_size_bytes, NIZKProof


PARAMS_TINY  = RSDParams.tiny()
PARAMS_SMALL = RSDParams.small()

# Use a small κ for fast tests
FAST_KAPPA = 10


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------

class TestNIZKCompleteness:
    def test_prove_verify_tiny(self):
        inst  = generate_instance(PARAMS_TINY)
        proof = prove(inst, kappa=FAST_KAPPA)
        assert verify_proof(inst, proof, kappa=FAST_KAPPA)

    def test_prove_verify_small(self):
        inst  = generate_instance(PARAMS_SMALL)
        proof = prove(inst, kappa=FAST_KAPPA)
        assert verify_proof(inst, proof, kappa=FAST_KAPPA)

    def test_multiple_fresh_instances(self):
        for _ in range(3):
            inst  = generate_instance(PARAMS_TINY)
            proof = prove(inst, kappa=FAST_KAPPA)
            assert verify_proof(inst, proof, kappa=FAST_KAPPA)


# ---------------------------------------------------------------------------
# Integrity: tampered proof should be rejected
# ---------------------------------------------------------------------------

class TestNIZKIntegrity:
    def test_wrong_CH_rejected(self):
        inst  = generate_instance(PARAMS_TINY)
        proof = prove(inst, kappa=FAST_KAPPA)
        bad   = copy.deepcopy(proof)
        bad.CH = os.urandom(32)
        assert not verify_proof(inst, bad, kappa=FAST_KAPPA)

    def test_flipped_e_share_rejected(self):
        inst  = generate_instance(PARAMS_SMALL)
        proof = prove(inst, kappa=FAST_KAPPA)
        bad   = copy.deepcopy(proof)
        bad.responses[0].e_ch1[0] ^= 0xFF
        assert not verify_proof(inst, bad, kappa=FAST_KAPPA)

    def test_wrong_kappa_rejected(self):
        inst  = generate_instance(PARAMS_TINY)
        proof = prove(inst, kappa=FAST_KAPPA)
        assert not verify_proof(inst, proof, kappa=FAST_KAPPA + 1)

    def test_proof_for_wrong_instance_rejected(self):
        """A proof for instance A should not verify for instance B."""
        inst_a = generate_instance(PARAMS_TINY)
        inst_b = generate_instance(PARAMS_TINY)
        proof  = prove(inst_a, kappa=FAST_KAPPA)
        # The verifier uses inst_b's (H, s), so the proof should fail
        assert not verify_proof(inst_b, proof, kappa=FAST_KAPPA)

    def test_truncated_responses_rejected(self):
        inst  = generate_instance(PARAMS_TINY)
        proof = prove(inst, kappa=FAST_KAPPA)
        bad   = copy.deepcopy(proof)
        bad.responses = bad.responses[:-1]   # drop one round
        assert not verify_proof(inst, bad, kappa=FAST_KAPPA)


# ---------------------------------------------------------------------------
# Meta / size checks
# ---------------------------------------------------------------------------

class TestNIZKMeta:
    def test_recommended_kappa(self):
        k = recommended_kappa(128)
        assert k == 219

    def test_proof_has_correct_number_of_responses(self):
        inst  = generate_instance(PARAMS_TINY)
        proof = prove(inst, kappa=FAST_KAPPA)
        assert len(proof.responses) == FAST_KAPPA

    def test_proof_size_estimate_paper(self):
        """
        Sanity-check Equation 7 of the paper: ~65.2 KB at 128-bit security.
        We allow ±20% tolerance since our serialisation may differ slightly.
        """
        size = proof_size_bytes(RSDParams.paper_128(), recommended_kappa(128))
        target_kb = 65.2 * 1024
        assert 0.8 * target_kb < size < 1.5 * target_kb, \
            f"Proof size estimate {size/1024:.1f} KB far from expected 65.2 KB"
