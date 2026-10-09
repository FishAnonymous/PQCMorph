#!/usr/bin/env python3
"""Offline evidence validation and recomputation; no OpenSSL processes are run."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pqcmorph import ALGORITHMS, FAMILIES, PROFILES, kem_oracle, tls_boundary, tls_ok, tls_rejected


def audit(directory):
    if sys.flags.optimize:
        raise RuntimeError("Audit requires enabled assertions; do not use python -O or PYTHONOPTIMIZE")
    directory = Path(directory)
    data = json.loads((directory / "results.json").read_text())
    commands = [json.loads(x) for x in (directory / "commands.jsonl").read_text().splitlines()]
    assert [x["id"] for x in commands] == list(range(len(commands))), "noncontiguous commands"

    def walk(obj):
        if isinstance(obj, dict):
            if "base64" in obj:
                raw = base64.b64decode(obj["base64"], validate=True)
                assert len(raw) == obj["bytes"] and hashlib.sha256(raw).hexdigest() == obj["sha256"]
            if "command" in obj and "id" in obj:
                raw = commands[obj["id"]]
                for k in ("command", "rc", "stderr", "stdout", "timeout", "ms"):
                    assert obj[k] == raw[k], (obj["id"], k)
                args = obj["command"]
                for field, flag in (("secret", "-secret"), ("ciphertext", "-out")):
                    if field in obj:
                        path = directory / args[args.index(flag) + 1]
                        content = path.read_bytes() if path.exists() else b""
                        assert content == base64.b64decode(obj[field]["base64"])
                if "group" in obj:
                    text = obj["stderr"] + obj["stdout"]
                    g = re.search(r"(?:Negotiated TLS1.3 group|Server Temp Key|Peer Temp Key):\s*([^,\s]+)", text)
                    v = re.search(r"Protocol version:\s*(\S+)", text)
                    assert obj["group"] == (g.group(1) if g else None)
                    assert obj["protocol"] == (v.group(1) if v else None)
                    assert (directory / obj["server_log"]).exists()
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(data)
    n = data["config"]["kem_trials"]
    assert len(data["kem"]) == 18 * n
    expected = {(a, t, f"K{k}") for a in ALGORITHMS for t in range(n) for k in range(1, 7)}
    assert {(x["algorithm"], x["trial"], x["relation"]) for x in data["kem"]} == expected
    for row in data["kem"]:
        rel, source, follow = row["relation"], row["source"], row["follow"]
        assert row["passed"] == kem_oracle(rel, source, follow)
        assert row["passed"], (row["algorithm"], row["trial"], rel)
        if rel in ("K2", "K6"):
            args = follow["command"]
            changed = (directory / args[args.index("-in") + 1]).read_bytes()
            ct = base64.b64decode(source["ciphertext"]["base64"])
            if rel == "K6":
                assert changed == ct[:-1]
            else:
                b = bytearray(ct)
                b[row["bit"] // 8] ^= 1 << (row["bit"] % 8)
                assert changed == bytes(b)
    n = data["config"]["tls_trials"]
    assert len(data["tls"]) == n * 16
    grid = {(x["trial"], x["server"], x["client"]): x["observed"] for x in data["tls"]}
    assert set(grid) == {(t, s, c) for t in range(n) for s in PROFILES for c in PROFILES}
    for row in data["tls"]:
        assert row["passed"] == tls_boundary(row["observed"], PROFILES[row["client"]], PROFILES[row["server"]])
        assert row["passed"]
    assert len(data["tls_relations"]) == n * 8
    for row in data["tls_relations"]:
        src = grid[row["trial"], *row["source"]]
        dst = grid[row["trial"], *row["follow"]]
        if row["relation"] == "T3":
            ok = tls_ok(src) and tls_rejected(dst)
        else:
            s, c = row["follow"]
            ok = tls_ok(src) and tls_boundary(dst, PROFILES[c], PROFILES[s])
        assert row["passed"] == ok and ok
    assert len(data["negative"]) == 4
    for row in data["negative"]:
        obs = row["observed"]
        ok = tls_rejected(obs) and obs["ms"] < data["config"]["timeout"] * 1000
        assert row["passed"] == ok and ok
    if "faults" in data:
        assert len(data["faults"]) == 60
        assert {(x["family"], x["variant"]) for x in data["faults"]} == {(f, v) for f in FAMILIES for v in range(6)}
        for row in data["faults"]:
            for label in ("control", "mutant"):
                case = row[label]
                checks = {k: kem_oracle(k, row["source"], v) for k, v in case["kem_observations"].items()}
                for name, obs in case["tls_observations"].items():
                    if name in ("HYBRID", "T1-PQ"):
                        sg, cg = ((PROFILES["Hybrid"], PROFILES["Hybrid"]) if name == "HYBRID"
                                  else (PROFILES["Mixed"], PROFILES["PQC"]))
                        checks[name] = tls_boundary(obs, cg, sg)
                    else:
                        checks[name] = tls_rejected(obs)
                assert case["checks"] == checks
                assert case["baseline_killed"] == any(not checks[k] for k in ("K1", "HYBRID", "EMPTY"))
                assert case["core_killed"] == any(not v for k, v in checks.items() if k not in ("EMPTY", "K4-REPLACE"))
                assert case["extended_killed"] == any(not v for v in checks.values())
            assert row["control_passed"] == all(row["control"]["checks"].values())
            assert row["control_passed"], "unmodified control failed"
    return data, len(commands)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", nargs="?", default="reference/core")
    a = p.parse_args()
    d, n = audit(a.directory)
    print(f"Offline audit PASS: {len(d['kem'])} KEM checks, {len(d['tls'])} TLS trials, "
          f"4 negative paths, {len(d.get('faults', []))} paired mutants; {n} command records")
