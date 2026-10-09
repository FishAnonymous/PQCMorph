#!/usr/bin/env python3
"""Compile and run the native benchmark against the selected OpenSSL prefix."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--out", required=True)
p.add_argument("--prefix", help="OpenSSL installation prefix; inferred from OPENSSL otherwise")
p.add_argument("--repetitions", type=int, default=8)
p.add_argument("--operations", type=int, default=2000)
a = p.parse_args()
if min(a.repetitions, a.operations) < 1:
    p.error("counts must be positive")
output = Path(a.out)
if output.exists() or output.with_suffix(".json").exists():
    p.error("output already exists; use a fresh path")
executable = shutil.which(os.environ.get("OPENSSL", "openssl"))
prefix = Path(a.prefix) if a.prefix else Path(executable).resolve().parent.parent
libs = [prefix / "lib", prefix / "lib64", *prefix.glob("lib/*-linux-gnu")]
lib = next((x for x in libs if (x / "libcrypto.so").exists()), None)
if lib is None or not (prefix / "include/openssl/evp.h").exists():
    p.error("headers/libcrypto unavailable; provide --prefix for an existing OpenSSL installation")
source = Path(__file__).resolve().parent.parent / "src/evp_bench.c"
output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="pqcmorph-bench-") as tmp:
    binary = Path(tmp) / "evp-bench"
    flags = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"]
    command = [os.environ.get("CC", "cc"), *flags, "-I" + str(prefix / "include"),
               str(source), "-L" + str(lib), "-Wl,-rpath," + str(lib), "-lcrypto", "-o", str(binary)]
    subprocess.run(command, check=True, capture_output=True)
    start = time.perf_counter()
    run = subprocess.run([str(binary), str(a.repetitions), str(a.operations)],
                         capture_output=True, text=True, check=True, timeout=300)
    elapsed = time.perf_counter() - start
    rows = list(csv.DictReader(run.stdout.splitlines()))
    if len(rows) != 9 * a.repetitions:
        raise RuntimeError("incomplete benchmark output")
    output.write_text(run.stdout)
    metadata = {"openssl_library": run.stderr.strip(), "seconds": elapsed,
                "repetitions": a.repetitions, "operations": a.operations,
                "compiler": subprocess.run([command[0], "--version"], capture_output=True,
                                            text=True, check=True).stdout.splitlines()[0],
                "flags": flags, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "libcrypto_sha256": hashlib.sha256((lib / "libcrypto.so").read_bytes()).hexdigest(),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "timing_scope": "reused EVP contexts; keygen includes allocation/free; encaps includes RNG; decaps reuses final valid ciphertext; no explicit warm-up"}
    output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
print(f"Native EVP: {len(rows)} measurements in {elapsed:.3f}s -> {output}")
