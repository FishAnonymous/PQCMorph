#!/usr/bin/env python3
"""Create an anonymous review ZIP from an explicit distribution allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--out", required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
output = Path(a.out).resolve()
if output.exists():
    p.error("archive already exists; choose a fresh output file")
files = [root / "README.md", root / ".gitignore"]
for name in ("src", "scripts", "tests", "docs", "assets", "reference"):
    files.extend(x for x in (root / name).rglob("*") if x.is_file()
                 and "__pycache__" not in x.parts and x.suffix != ".pyc")
files = sorted(files)
if any(x.is_symlink() for x in files):
    raise SystemExit("Symlinks are not packaged")
for path in files:
    if path.suffix in (".py", ".c", ".md", ".json", ".jsonl", ".html", ".log"):
        data = path.read_bytes()
        if any(token in data.lower() for token in (b"/" + b"home/", b"/" + b"mnt/")):
            raise SystemExit(f"Review identifying content before packaging: {path.relative_to(root)}")
manifest = {"format": 1, "files": {str(x.relative_to(root)): hashlib.sha256(x.read_bytes()).hexdigest() for x in files}}
(root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
files.append(root / "MANIFEST.json")
with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for path in files:
        info = zipfile.ZipInfo("PQCMorph/" + str(path.relative_to(root)))
        # Fixed non-identifying metadata; no usernames, absolute paths or host mtimes.
        info.date_time = (2026, 1, 1, 0, 0, 0)
        info.external_attr = 0o100644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, path.read_bytes(), compresslevel=9)
with zipfile.ZipFile(output) as z:
    bad = z.testzip()
    if bad:
        raise SystemExit("ZIP CRC failure: " + bad)
print(f"{len(files)} files; {output.stat().st_size / 1024**2:.2f} MiB -> {output}")
