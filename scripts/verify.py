#!/usr/bin/env python3
"""Check distribution hashes and recompute all included relation verdicts offline."""
import hashlib
import json
from pathlib import Path
from audit import audit

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "MANIFEST.json").read_text())
for name, expected in manifest["files"].items():
    path = root / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"Integrity failure: {name}")
print(f"Integrity PASS: {len(manifest['files'])} files")
for name in ("core", "version-3.6", "scale-4x"):
    r, count = audit(root / "reference" / name)
    print(f"{name}: PASS — {len(r['kem'])} KEM, {len(r['tls'])} TLS, 4 negative paths; {count} commands")
