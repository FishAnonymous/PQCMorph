import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pqcmorph import blob, kem_oracle, tls_boundary, tls_ok, tls_rejected

def observation(secret=b"a" * 32, rc=0, timeout=False):
    return dict(secret=blob(secret), ciphertext=blob(b"c" * 768), rc=rc, timeout=timeout)

class OracleTests(unittest.TestCase):
    def test_implicit_rejection_is_not_an_error_oracle(self):
        self.assertTrue(kem_oracle("K2", observation(), observation(b"b" * 32)))
        self.assertFalse(kem_oracle("K2", observation(), observation()))

    def test_truncation_must_not_emit_secret(self):
        self.assertTrue(kem_oracle("K6", observation(), observation(b"", 1)))
        self.assertFalse(kem_oracle("K6", observation(), observation(b"b" * 32, 1)))
        self.assertFalse(kem_oracle("K6", observation(), observation(b"", 0)))

    def test_timeouts_and_crashes_are_not_valid_rejections(self):
        for rc, timeout in [(124, True), (-11, False)]:
            for rel in ("K2", "K3", "K6"):
                self.assertFalse(kem_oracle(rel, observation(), observation(b"", rc, timeout)))
            self.assertFalse(tls_rejected(dict(rc=rc, timeout=timeout, stderr="alert failure")))

    def test_bad_source_cannot_pass(self):
        for rel in ("K1", "K2", "K3", "K4", "K5", "K6"):
            self.assertFalse(kem_oracle(rel, observation(b"", 1), observation(b"", 1)))

    def test_freshness_uses_pair_inequality(self):
        self.assertFalse(kem_oracle("K5", observation(), observation()))
        follow = observation()
        follow["ciphertext"] = blob(b"different")
        self.assertTrue(kem_oracle("K5", observation(), follow))

    def test_tls_exit_code_alone_is_insufficient(self):
        self.assertFalse(tls_ok(dict(rc=0, timeout=False, stderr="")))
        self.assertFalse(tls_rejected(dict(rc=1, timeout=False, stderr="Connection refused")))

    def test_successful_downgrade_is_failure(self):
        o = dict(rc=0, timeout=False, stderr="CONNECTION ESTABLISHED",
                 group="X25519", protocol="TLSv1.3")
        self.assertFalse(tls_boundary(o, "X25519", "X25519MLKEM768"))
        self.assertTrue(tls_boundary(o, "X25519", "X25519"))

    def test_serialization_bypass_needs_extra_observable(self):
        self.assertTrue(kem_oracle("K4", observation(), observation()))
        self.assertFalse(kem_oracle("K4-REPLACE", observation(), observation()))

if __name__ == "__main__":
    unittest.main()
