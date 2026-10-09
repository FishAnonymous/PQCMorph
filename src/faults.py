"""Executable wrapper faults, reconstructed from the ten paper fault families.

No oracle receives a mutant family/identifier. Adapters alter arguments/material
before calling OpenSSL. The original sixty variant definitions were unavailable.
"""
import base64
import itertools
from pqcmorph import ALGORITHMS, FAMILIES, PROFILES, kem_oracle, tls_boundary, tls_ok, tls_rejected


class Adapter:
    def __init__(self, runner, family, variant, key, wrong, source):
        self.r, self.family, self.variant = runner, family, variant
        self.key, self.wrong, self.source = key, wrong, source
        self.ct = base64.b64decode(source["ciphertext"]["base64"])
        self.trace = []

    def decap(self, key, ct):
        requested_key, requested_ct = key, ct
        if self.family == "KEM-WRONG-KEY" and key == self.key:
            if self.variant < 3 or ct == self.ct:
                key = self.wrong
        elif self.family == "CT-ALIAS" and len(ct) == len(self.ct) and ct != self.ct:
            # Two cache implementations: ciphertext lookup versus cached key+ct pair.
            ct = self.ct
            if self.variant >= 3:
                key = self.key
        elif self.family == "WRONG-KEY-ALIAS" and key != self.key:
            key = self.key
            if self.variant >= 3:
                ct = self.ct
        elif self.family == "TRUNC-PAD" and len(ct) < len(self.ct):
            missing = len(self.ct) - len(ct)
            # 0/1 repair every short input; 2/4 repair only one byte; 3/5 up to two.
            limit = [len(self.ct), len(self.ct), 1, 2, 1, 2][self.variant]
            if missing <= limit:
                ct += self.ct[len(ct):] if self.variant in (0, 2, 3) else bytes(missing)
        obs = self.r.decap(key, ct)
        if key != requested_key or ct != requested_ct:
            self.trace.append({"command_id": obs["id"], "requested_key": requested_key,
                               "actual_key": key, "requested_ct_bytes": len(requested_ct),
                               "actual_ct_bytes": len(ct), "operation": "decap"})
        return obs

    def reload(self, key):
        if self.family == "SERIALIZE-BYPASS":
            # Variant 0..2 returns the cached handle; 3..5 reserializes the cached key.
            actual = self.key
            self.trace.append({"operation": "reload", "requested_key": key,
                               "actual_key": actual})
            return actual if self.variant < 3 else self.r.serialize(actual)
        return self.r.serialize(key)

    def handshake(self, server, client, version="-tls1_3"):
        original = [server, client, version]
        if self.family == "TLS-HYBRID-TYPO":
            typos = ["X25519MLKEM76", "X25519MLKEM786", "X25519_MLKEM768",
                     "X25519MLKEM-768", "X25519MLKEM769", "X25519MLKEM768x"]
            client = client.replace("X25519MLKEM768", typos[self.variant])
        elif self.family == "SILENT-FALLBACK" and server == PROFILES["Hybrid"]:
            server = ":".join(list(itertools.permutations(PROFILES["Mixed"].split(":")))[self.variant])
        elif self.family == "DROP-PQ" and server == PROFILES["Mixed"]:
            replacements = ["", "X448", "P-256", "P-384", "P-521", "X25519"]
            groups = [x for x in server.split(":") if x != "MLKEM768"]
            extra = replacements[self.variant]
            if extra and extra not in groups:
                groups.append(extra)
            server = ":".join(groups)
        elif self.family == "VERSION-FORCE" and version == "-tls1_2":
            version = "-tls1_3"
            # Six preference lists all retain the hybrid group.
            lists = ["X25519MLKEM768", "X25519MLKEM768:X25519", "X25519:X25519MLKEM768",
                     "X25519MLKEM768:MLKEM768", "MLKEM768:X25519MLKEM768", PROFILES["Mixed"]]
            client = lists[self.variant]
        elif self.family == "UNKNOWN-SUBSTITUTE" and "UnknownPQGroup" in client:
            client = ["X25519", "X25519:P-256", "P-256:X25519", "X448:X25519",
                      "X25519:P-384", "X25519:P-521"][self.variant]
        obs = self.r.handshake(server, client, version)
        if original != [server, client, version]:
            self.trace.append({"operation": "tls", "command_id": obs["id"],
                               "requested": original, "actual": [server, client, version]})
        return obs


def evaluate(adapter, public):
    """Identical, non-short-circuiting tests for controls and every mutant."""
    a, r, source = adapter, adapter.r, adapter.source
    ct = a.ct
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    follows = {"K1": a.decap(a.key, ct), "K2": a.decap(a.key, flipped),
               "K3": a.decap(a.wrong, ct), "K4": a.decap(a.reload(a.key), ct),
               "K5": r.encap(public), "K6": a.decap(a.key, ct[:-1]),
               "EMPTY": a.decap(a.key, b""),
               "K4-REPLACE": a.decap(a.reload(a.wrong), ct)}
    outcomes = {k: kem_oracle(k, source, v) for k, v in follows.items()}
    h, c, p, m = [PROFILES[x] for x in ("Hybrid", "Classical", "PQC", "Mixed")]
    specs = {"HYBRID": (h, h, "-tls1_3", True),
             "T3": (h, c, "-tls1_3", False),
             "T1-PQ": (m, p, "-tls1_3", True),
             "T4": (h, h, "-tls1_2", False),
             "T5": (m, "UnknownPQGroup", "-tls1_3", False)}
    tls = {}
    for name, (sg, cg, version, expected) in specs.items():
        obs = a.handshake(sg, cg, version)
        tls[name] = obs
        outcomes[name] = tls_boundary(obs, cg, sg) if expected else tls_rejected(obs)
    baseline = ["K1", "HYBRID", "EMPTY"]
    core = ["K1", "K2", "K3", "K4", "K5", "K6", "HYBRID", "T3", "T1-PQ", "T4", "T5"]
    return {"checks": outcomes, "kem_observations": follows, "tls_observations": tls,
            "baseline_killed": any(not outcomes[x] for x in baseline),
            "core_killed": any(not outcomes[x] for x in core),
            "extended_killed": any(not v for v in outcomes.values()),
            "trace": a.trace}


def run_faults(r):
    rows = []
    for family in FAMILIES:
        for variant in range(6):
            algorithm = ALGORITHMS[variant % 3]
            key, wrong = r.key(algorithm), r.key(algorithm)
            public = r.public(key)
            source = r.encap(public)
            control = evaluate(Adapter(r, None, variant, key, wrong, source), public)
            mutant = evaluate(Adapter(r, family, variant, key, wrong, source), public)
            rows.append(dict(family=family, variant=variant, algorithm=algorithm,
                             source=source, control=control, mutant=mutant,
                             control_passed=all(control["checks"].values())))
        print(f"  Faults {family}: 6 paired control/mutant cases", flush=True)
    return rows
