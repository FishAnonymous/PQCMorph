#!/usr/bin/env python3
"""Paper-derived PQC migration experiments; Python standard library only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import selectors
import shutil
import socket
import subprocess
import threading
import time

ALGORITHMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
PROFILES = {"Classical": "X25519", "Hybrid": "X25519MLKEM768",
            "PQC": "MLKEM768", "Mixed": "X25519MLKEM768:X25519:MLKEM768"}
FAMILIES = ["KEM-WRONG-KEY", "TLS-HYBRID-TYPO", "CT-ALIAS", "WRONG-KEY-ALIAS",
            "TRUNC-PAD", "SERIALIZE-BYPASS", "SILENT-FALLBACK", "DROP-PQ",
            "VERSION-FORCE", "UNKNOWN-SUBSTITUTE"]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def blob(data):
    return {"bytes": len(data), "sha256": digest(data),
            "base64": base64.b64encode(data).decode()}

def kem_oracle(relation, source, follow, second=None):
    """Infrastructure failures never satisfy a negative-path relation."""
    if source["rc"] != 0 or source["timeout"] or source["secret"]["bytes"] != 32:
        return False
    if follow["timeout"] or follow["rc"] < 0:
        return False
    same = source["secret"]["sha256"] == follow["secret"]["sha256"]
    if relation in ("K1", "K4"):
        return follow["rc"] == 0 and follow["secret"]["bytes"] == 32 and same
    if relation in ("K2", "K3", "K4-REPLACE"):
        return ((follow["rc"] == 0 and follow["secret"]["bytes"] == 32 and not same)
                or (follow["rc"] > 0 and follow["secret"]["bytes"] == 0))
    if relation == "K5":
        return (follow["rc"] == 0 and follow["secret"]["bytes"] == 32
                and (not same or source["ciphertext"]["sha256"] != follow["ciphertext"]["sha256"]))
    if relation in ("K6", "EMPTY"):
        return follow["rc"] > 0 and follow["secret"]["bytes"] == 0
    raise ValueError(relation)

def tls_ok(obs):
    return (obs["rc"] == 0 and not obs["timeout"]
            and "CONNECTION ESTABLISHED" in obs["stderr"])

def tls_rejected(obs):
    # A timeout, signal, missing executable, or unreachable server is not a valid rejection.
    message = obs["stderr"].lower()
    return (obs["rc"] > 0 and not obs["timeout"] and not tls_ok(obs)
            and any(x in message for x in ("alert", "unexpected eof", "write:errno=104",
                                           "read:errno=104", "ssl_conf_cmd", "group '")))

def tls_boundary(obs, client_groups, server_groups):
    allowed = set(client_groups.split(":")) & set(server_groups.split(":"))
    if allowed:
        return tls_ok(obs) and obs["group"] in allowed and obs["protocol"] == "TLSv1.3"
    return tls_rejected(obs)

class Runner:
    def __init__(self, output, openssl, timeout=5):
        self.root = Path(output).resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.openssl = shutil.which(openssl)
        if not self.openssl:
            raise RuntimeError("OpenSSL executable unavailable")
        self.timeout = timeout
        self.commands = []
        self.counter = 0
        self.root.joinpath("material").mkdir()
        self.env = dict(os.environ, LC_ALL="C")

    def path(self, label):
        self.counter += 1
        return f"material/{self.counter:06d}-{label}"

    def put(self, name, data):
        self.root.joinpath(name).write_bytes(data)
        return name

    def read(self, name):
        p = self.root / name
        return p.read_bytes() if p.exists() else b""

    def run(self, args, input=b"", required=False):
        start = time.perf_counter()
        try:
            p = subprocess.run([self.openssl] + list(args), input=input, capture_output=True,
                               cwd=self.root, timeout=self.timeout, env=self.env)
            rc, out, err, timeout = p.returncode, p.stdout, p.stderr, False
        except subprocess.TimeoutExpired as e:
            rc, out, err, timeout = 124, e.stdout or b"", e.stderr or b"", True
        obs = {"id": len(self.commands), "command": ["openssl"] + list(args),
               "rc": rc, "stdout": out.decode(errors="replace"),
               "stderr": err.decode(errors="replace"), "timeout": timeout,
               "ms": (time.perf_counter() - start) * 1000}
        self.commands.append(obs)
        with (self.root / "commands.jsonl").open("a") as f:
            f.write(json.dumps(obs) + "\n")
        if required and (rc != 0 or timeout):
            raise RuntimeError(f"Command {obs['id']} failed: {obs['stderr']}")
        return obs

    def key(self, algorithm):
        name = self.path("key.pem")
        self.run(["genpkey", "-algorithm", algorithm, "-out", name], required=True)
        return name

    def public(self, key):
        name = self.path("public.pem")
        self.run(["pkey", "-in", key, "-pubout", "-out", name], required=True)
        return name

    def encap(self, public):
        ct, ss = self.path("ct.bin"), self.path("ss.bin")
        o = self.run(["pkeyutl", "-encap", "-pubin", "-inkey", public,
                      "-out", ct, "-secret", ss])
        return dict(o, ciphertext=blob(self.read(ct)), secret=blob(self.read(ss)), ct_path=ct)

    def decap(self, key, ciphertext):
        inp, ss = self.path("input.bin"), self.path("decap.bin")
        self.put(inp, ciphertext)
        o = self.run(["pkeyutl", "-decap", "-inkey", key, "-in", inp, "-secret", ss])
        return dict(o, secret=blob(self.read(ss)))

    def serialize(self, key):
        der, pem = self.path("key.der"), self.path("reloaded.pem")
        self.run(["pkey", "-in", key, "-outform", "DER", "-out", der], required=True)
        self.run(["pkey", "-inform", "DER", "-in", der, "-out", pem], required=True)
        return pem

    def certificate(self):
        if hasattr(self, "cert"):
            return
        self.cert, self.certkey = self.path("tls-cert.pem"), self.path("tls-key.pem")
        self.run(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-noenc", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                  "-days", "2", "-keyout", self.certkey, "-out", self.cert], required=True)

    def handshake(self, server_groups, client_groups, version="-tls1_3", abrupt=False):
        self.certificate()
        # Bind only to loopback; a fresh server owns every trial.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        proc = None
        thread = None
        start = time.perf_counter()
        server_log = self.path("server.log")
        server_args = []
        with (self.root / server_log).open("wb") as log:
            if abrupt:
                listener.listen(1)
                listener.settimeout(self.timeout)
                def close_peer():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(self.timeout)
                            connection.recv(1)
                    except (TimeoutError, OSError):
                        pass
                thread = threading.Thread(target=close_peer, daemon=True)
                thread.start()
            else:
                listener.close()
                server_args = ["s_server", "-accept", f"127.0.0.1:{port}",
                               "-cert", self.cert, "-key", self.certkey,
                               "-tls1_3", "-groups", server_groups, "-www"]
                proc = subprocess.Popen([self.openssl] + server_args, cwd=self.root,
                                        stdout=log, stderr=log, env=self.env)
                # Wait for the explicit ACCEPT marker, not an extra TCP probe.
                deadline = time.monotonic() + self.timeout
                while b"ACCEPT" not in self.read(server_log):
                    if proc.poll() is not None:
                        raise RuntimeError("TLS server startup failed: " + self.read(server_log).decode())
                    if time.monotonic() >= deadline:
                        proc.kill()
                        proc.wait()
                        raise RuntimeError("TLS server readiness timeout")
                    time.sleep(0.002)
            try:
                obs = self.run(["s_client", "-connect", f"127.0.0.1:{port}",
                                "-servername", "localhost", "-verify_hostname", "localhost",
                                "-CAfile", self.cert, "-verify_return_error", "-brief",
                                "-no_ign_eof", version, "-groups", client_groups])
            finally:
                if proc:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                if thread:
                    thread.join(timeout=self.timeout)
                listener.close()
        text = obs["stderr"] + obs["stdout"]
        group = re.search(r"(?:Negotiated TLS1.3 group|Server Temp Key|Peer Temp Key):\s*([^,\s]+)", text)
        protocol = re.search(r"Protocol version:\s*(\S+)", text)
        return dict(obs, group=group.group(1) if group else None,
                    protocol=protocol.group(1) if protocol else None,
                    server_command=["openssl"] + server_args if server_args else ["python", "close-peer"],
                    server_log=server_log, server_groups=server_groups, client_groups=client_groups,
                    total_ms=(time.perf_counter() - start) * 1000)


def run_kem(r, trials, seed):
    rng = random.Random(seed)
    rows = []
    for algorithm in ALGORITHMS:
        key, wrong = r.key(algorithm), r.key(algorithm)
        public = r.public(key)
        for trial in range(trials):
            source = r.encap(public)
            ct = base64.b64decode(source["ciphertext"]["base64"])
            altered = bytearray(ct)
            bit = rng.randrange(len(ct) * 8)
            altered[bit // 8] ^= 1 << (bit % 8)
            follows = {"K1": r.decap(key, ct), "K2": r.decap(key, bytes(altered)),
                       "K3": r.decap(wrong, ct), "K4": r.decap(r.serialize(key), ct),
                       "K5": r.encap(public), "K6": r.decap(key, ct[:-1])}
            for relation, follow in follows.items():
                rows.append(dict(algorithm=algorithm, trial=trial, relation=relation,
                                 bit=bit if relation == "K2" else None, source=source,
                                 follow=follow, passed=kem_oracle(relation, source, follow)))
        print(f"  KEM {algorithm}: {trials * 6} checks", flush=True)
    return rows


def run_tls(r, trials):
    rows, relations = [], []
    for trial in range(trials):
        grid = {}
        for server, sg in PROFILES.items():
            for client, cg in PROFILES.items():
                obs = r.handshake(sg, cg)
                ok = tls_boundary(obs, cg, sg)
                grid[server, client] = obs
                rows.append(dict(server=server, client=client, trial=trial,
                                 observed=obs, passed=ok))
        for profile in ("Classical", "Hybrid", "PQC"):
            for s, c in ((profile, "Mixed"), ("Mixed", profile)):
                source, follow = grid[profile, profile], grid[s, c]
                relations.append(dict(relation="T2", trial=trial, source=[profile, profile],
                                      follow=[s, c], passed=tls_ok(source) and
                                      tls_boundary(follow, PROFILES[c], PROFILES[s])))
        for profile in ("Hybrid", "PQC"):
            relations.append(dict(relation="T3", trial=trial, source=[profile, profile],
                                  follow=[profile, "Classical"],
                                  passed=tls_ok(grid[profile, profile]) and
                                  tls_rejected(grid[profile, "Classical"])))
        print(f"  TLS matrix repetition {trial + 1}: 16 handshakes", flush=True)
    return rows, relations


def run_negative(r):
    specs = [("version-mismatch", "T4", "X25519MLKEM768", "X25519MLKEM768", "-tls1_2", False),
             ("no-common-group", "T3", "X25519MLKEM768", "X25519", "-tls1_3", False),
             ("abrupt-close", "T6", "X25519MLKEM768", "X25519MLKEM768", "-tls1_3", True),
             ("unknown-group", "T5", "X25519MLKEM768", "UnknownPQGroup", "-tls1_3", False)]
    return [dict(scenario=name, relation=rel, observed=(o := r.handshake(s, c, v, a)),
                 passed=tls_rejected(o) and o["ms"] < r.timeout * 1000)
            for name, rel, s, c, v, a in specs]


def environment(r):
    cpu = "unknown"
    if Path("/proc/cpuinfo").exists():
        match = re.search(r"model name\s*:\s*(.+)", Path("/proc/cpuinfo").read_text())
        cpu = match.group(1) if match else cpu
    return {"openssl": r.run(["version"], required=True)["stdout"].strip(),
            "openssl_sha256": digest(Path(r.openssl).read_bytes()),
            "python": platform.python_version(), "os": platform.system(),
            "kernel": platform.release(), "machine": platform.machine(),
            "cpu": cpu, "logical_cpus": os.cpu_count(),
            "randomness": "OS entropy for cryptography; seeded Python PRNG for bit positions only"}


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="New output directory (must not exist)")
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"))
    parser.add_argument("--kem-trials", type=int, default=40)
    parser.add_argument("--tls-trials", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1546)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--faults", action="store_true")
    args = parser.parse_args()
    if min(args.kem_trials, args.tls_trials, args.timeout) <= 0:
        parser.error("trial counts and timeout must be positive")
    r = Runner(args.out, args.openssl, args.timeout)
    start = time.perf_counter()
    result = {"schema": 1, "environment": environment(r),
              "config": {k: v for k, v in vars(args).items() if k not in ("out", "openssl")}}
    result["kem"] = run_kem(r, args.kem_trials, args.seed)
    result["tls"], result["tls_relations"] = run_tls(r, args.tls_trials)
    result["negative"] = run_negative(r)
    result["core_seconds"] = time.perf_counter() - start
    if args.faults:
        from faults import run_faults
        t = time.perf_counter()
        result["faults"] = run_faults(r)
        result["fault_seconds"] = time.perf_counter() - t
    result["seconds"] = time.perf_counter() - start
    write_json(r.root / "results.json", result)
    failed = sum(not x["passed"] for section in ("kem", "tls", "tls_relations", "negative")
                 for x in result[section])
    if args.faults:
        failed += sum(not x["control_passed"] for x in result["faults"])
    print(f"Results: {args.out}/results.json; unexpected failures: {failed}")
    return int(failed != 0)


if __name__ == "__main__":
    raise SystemExit(main())
