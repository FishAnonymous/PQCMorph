#!/usr/bin/env python3
"""Run a fresh end-to-end experiment without overwriting included evidence."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--out", required=True)
p.add_argument("--quick", action="store_true", help="18 KEM checks, 16 TLS trials, no mutants, tiny benchmark")
p.add_argument("--seed", type=int, default=1546)
p.add_argument("--prefix", help="Existing OpenSSL development prefix for the native benchmark")
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
out = Path(a.out).resolve()
out.mkdir(parents=True, exist_ok=False)
commands = [[sys.executable, str(root / "src/pqcmorph.py"), "--out", str(out / "core"),
             "--seed", str(a.seed), *( ["--kem-trials", "1", "--tls-trials", "1"] if a.quick else ["--faults"])],
            [sys.executable, str(root / "scripts/benchmark.py"), "--out", str(out / "native.csv"),
             *(["--repetitions", "1", "--operations", "20"] if a.quick else []),
             *(["--prefix", a.prefix] if a.prefix else [])],
            [sys.executable, str(root / "scripts/report.py"), "--input", str(out / "core"),
             "--native", str(out / "native.csv"), "--out", str(out / "report")]]
for command in commands:
    subprocess.run(command, check=True, cwd=root)
print(f"Complete: {out}/report/index.html")
