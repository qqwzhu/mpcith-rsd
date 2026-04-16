"""
Tests for the single-round interactive protocol (Section 3.3).

Covers:
  - Completeness: honest prover always accepted
  - All three challenge values
  - Soundness sanity: tampered commitment should fail
  - Auxiliary data handling (P₃ case)
"""

import pytest
import copy
from mpci_head.rsd import generate_instance, RSDParams
from mpci_head.protocol import Prover, Verifier, run_interactive_round


PARAMS_TINY  = RSDParams.tiny()
PARAMS_SMALL = RSDParams.small()


# ---------------------------------------------------------------------------
# Completeness tests
# ---------------------------------------------------------------------------

class TestCompleteness:
    @pytest.mark.parametrize("ch", [1, 2, 3])
    def test_honest_accepted_tiny(self, ch):
        inst = generate_instance(PARAMS_TINY)
        result = run_interactive_round(inst, ch=ch)
        assert result, f"Honest prover rejected for ch={ch}"

    @pytest.mark.parametrize("ch", [1, 2, 3])
    def test_honest_accepted_small(self, ch):
        inst = generate_instance(PARAMS_SMALL)
        result = run_interactive_round(inst, ch=ch)
        assert result, f"Honest prover rejected for ch={ch}"

    def test_completeness_multiple_rounds(self):
        """Run 30 random rounds and check all pass."""
        inst = generate_instance(PARAMS_SMALL)
        for _ in range(30):
            assert run_interactive_round(inst)

    def test_fresh_instance_each_time(self):
        """Different instances, all should verify."""
        for _ in range(5):
            inst = generate_instance(PARAMS_TINY)
            assert run_interactive_round(inst)


# ---------------------------------------------------------------------------
# Tampered response → should fail
# ---------------------------------------------------------------------------

class TestSoundnessSanity:
    def _get_honest_proof(self, params):
        inst = generate_instance(params)
        prv  = Prover(inst)
        ver  = Verifier(inst)
        C    = prv.commit()
        ver.receive_commitment(C)
        rsp  = prv.respond(1)
        return inst, ver, rsp

    def test_flipped_e_ch1_rejected(self):
        """Flip one bit of e_{ch+1} → verifier must reject."""
        inst, ver, rsp = self._get_honest_proof(PARAMS_SMALL)
        bad_rsp = copy.deepcopy(rsp)
        bad_rsp.e_ch1[0] ^= 0xFF     # corrupt error share
        assert not ver.verify(bad_rsp)

    def test_wrong_C_ch2_rejected(self):
        """Replace C_{ch+2} with random bytes → verifier must reject."""
        import os
        inst, ver, rsp = self._get_honest_proof(PARAMS_SMALL)
        bad_rsp = copy.deepcopy(rsp)
        bad_rsp.C_ch2 = os.urandom(32)
        assert not ver.verify(bad_rsp)

    def test_wrong_commitment_accepted_original_rejected(self):
        """Verifier with tampered stored C rejects a valid response."""
        import os
        inst = generate_instance(PARAMS_SMALL)
        prv  = Prover(inst)
        ver  = Verifier(inst)
        prv.commit()
        ver.receive_commitment(os.urandom(32))   # store garbage commitment
        rsp = prv.respond(2)
        assert not ver.verify(rsp)


# ---------------------------------------------------------------------------
# Protocol structure tests
# ---------------------------------------------------------------------------

class TestProtocolStructure:
    def test_respond_before_commit_raises(self):
        inst = generate_instance(PARAMS_TINY)
        prv  = Prover(inst)
        with pytest.raises(RuntimeError):
            prv.respond(1)

    def test_verify_before_commitment_raises(self):
        inst = generate_instance(PARAMS_TINY)
        prv  = Prover(inst)
        ver  = Verifier(inst)
        C    = prv.commit()
        rsp  = prv.respond(1)
        # Do NOT call ver.receive_commitment(C)
        with pytest.raises(RuntimeError):
            ver.verify(rsp)

    def test_invalid_challenge_raises(self):
        inst = generate_instance(PARAMS_TINY)
        prv  = Prover(inst)
        prv.commit()
        with pytest.raises(ValueError):
            prv.respond(0)
        with pytest.raises(ValueError):
            prv.respond(4)

    def test_all_challenges_produce_distinct_responses(self):
        """Each challenge value should produce a different response."""
        inst = generate_instance(PARAMS_SMALL)
        prv  = Prover(inst)
        prv.commit()
        rsps = [prv.respond(ch) for ch in (1, 2, 3)]
        seeds = [(r.seed_ch, r.seed_ch1) for r in rsps]
        # At least the seed pairs should differ across challenges
        assert len(set(seeds)) == 3
