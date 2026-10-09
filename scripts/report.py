#!/usr/bin/env python3
"""Recompute tables and paired statistics from measured observations."""
import argparse
import csv
from collections import defaultdict
import html
import json
import math
from pathlib import Path
import statistics
from audit import audit

def exact_p(b, c):
    n = b + c
    return min(1.0, 2 * sum(math.comb(n, k) for k in range(min(b, c) + 1)) / 2 ** n) if n else 1.0

def report_html(markdown):
    """Render this script's small, fixed Markdown vocabulary without dependencies."""
    fragments, in_table = [], False
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = [x.strip() for x in line.strip("|").split("|")]
            if all(set(x) <= {"-", ":", " "} for x in cells):
                continue
            tag = "td" if in_table else "th"
            if not in_table:
                fragments.append("<div class='table-wrap'><table>")
                in_table = True
            fragments.append("<tr>" + "".join(f"<{tag}>{html.escape(x)}</{tag}>" for x in cells) + "</tr>")
            continue
        if in_table:
            fragments.append("</table></div>")
            in_table = False
        if line.startswith("# "):
            continue
        if line.startswith("## "):
            fragments.append("<h2>" + html.escape(line[3:]) + "</h2>")
        elif line:
            fragments.append("<p>" + html.escape(line.removeprefix("- ")) + "</p>")
    if in_table:
        fragments.append("</table></div>")
    return "\n".join(fragments)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", default="reference/core")
    p.add_argument("--native", default="reference/native.csv")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    r, _ = audit(a.input)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=False)
    lines = ["# PQCMorph — measured reconstruction", "",
             "Independent implementation from the manuscript; original source and raw data were unavailable.", "",
             "## Environment", "", f"- {r['environment']['openssl']}",
             f"- CPU: {r['environment']['cpu']}; Python {r['environment']['python']}",
             f"- KEM/TLS/negative-path runtime: {r['core_seconds']:.3f} s", "",
             "## KEM relations (paper Table 3)", "",
             "| Algorithm | K1 | K2 | K3 | K4 | K5 | K6 |", "|---|---|---|---|---|---|---|"]
    for algorithm in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        cells = []
        for k in range(1, 7):
            subset = [x for x in r["kem"] if x["algorithm"] == algorithm and x["relation"] == f"K{k}"]
            cells.append(f"{sum(x['passed'] for x in subset)}/{len(subset)}")
        lines.append("| " + " | ".join([algorithm, *cells]) + " |")
    names = ["Classical", "Hybrid", "PQC", "Mixed"]
    lines += ["", "## TLS compatibility (paper Table 4)", "",
              "| Server / Client | Classical | Hybrid | PQC | Mixed |", "|---|---|---|---|---|"]
    matrix = []
    for server in names:
        cells, values = [], []
        for client in names:
            subset = [x for x in r["tls"] if x["server"] == server and x["client"] == client]
            groups = {x["observed"]["group"] or "reject" for x in subset}
            cells.append(", ".join(sorted(groups)) + f" ({len(subset)} trials)")
            values.append(sum(x["observed"]["rc"] == 0 for x in subset) / len(subset))
        matrix.append(values)
        lines.append("| " + " | ".join([server, *cells]) + " |")
    lines += ["", "## Negative paths (paper Table 5)", "",
              "| Scenario | Outcome | Client time (ms) |", "|---|---|---|"]
    for row in r["negative"]:
        lines.append(f"| {row['scenario']} | {'PASS' if row['passed'] else 'FAIL'} | {row['observed']['ms']:.3f} |")
    faults = []
    if r.get("faults"):
        lines += ["", "## Reconstructed faults (paper Table 6 comparison)", "",
                  "These are new executable wrapper mutants, not the lost original sixty variants.", "",
                  "| Family | Smoke | Paper-defined core | Core + key-replacement check |", "|---|---|---|---|"]
        for family in dict.fromkeys(x["family"] for x in r["faults"]):
            subset = [x for x in r["faults"] if x["family"] == family]
            counts = [sum(x["mutant"][k] for x in subset) for k in ("baseline_killed", "core_killed", "extended_killed")]
            faults.append([family, *counts])
            lines.append("| " + " | ".join([family, *(f"{n}/6" for n in counts)]) + " |")
        totals = [sum(x[i] for x in faults) for i in (1, 2, 3)]
        lines.append("| Total | " + " | ".join(f"{x}/60" for x in totals) + " |")
        for key, label in (("core_killed", "core"), ("extended_killed", "extended")):
            b = sum(x["mutant"][key] and not x["mutant"]["baseline_killed"] for x in r["faults"])
            c = sum(not x["mutant"][key] and x["mutant"]["baseline_killed"] for x in r["faults"])
            lines += ["", f"Smoke vs {label}: discordant pairs ({b}, {c}); two-sided exact McNemar p = {exact_p(b,c):.8g}."]
        lines += ["", "K4 compares the same key before/after reload. A cached original key can satisfy it. "
                  "K4-REPLACE substitutes an independent stored key and tests separation; this is an explicitly added relation.",
                  "", f"Unmodified controls: {sum(x['control_passed'] for x in r['faults'])}/60 pass. "
                  f"Paired fault campaign runtime: {r['fault_seconds']:.3f} s."]
    native = []
    if Path(a.native).exists():
        samples = list(csv.DictReader(Path(a.native).open()))
        metadata = json.loads(Path(a.native).with_suffix(".json").read_text())
        cli = r["environment"]["openssl"]
        assert cli.startswith(metadata["openssl_library"] + " (Library: "), "CLI/library version mismatch"
        assert cli.endswith("Library: " + metadata["openssl_library"] + ")"), "CLI/library version mismatch"
        assert len(samples) == 9 * metadata["repetitions"]
        lines += ["", "## Native EVP benchmark (paper Table 7)", "",
                  f"Mean ± sample standard deviation; {metadata['repetitions']} repetitions × {metadata['operations']} operations.", "",
                  "| Algorithm | KeyGen (µs) | Encaps (µs) | Decaps (µs) | CT bytes |", "|---|---|---|---|---|"]
        for algorithm in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
            stats = []
            for op in ("keygen", "encaps", "decaps"):
                vals = [float(x["us"]) for x in samples if x["algorithm"] == algorithm and x["operation"] == op]
                assert len(vals) == metadata["repetitions"] and all(x > 0 for x in vals)
                stats.append((statistics.mean(vals), statistics.stdev(vals) if len(vals) > 1 else 0))
            size = next(x["ct_bytes"] for x in samples if x["algorithm"] == algorithm)
            lines.append("| " + " | ".join([algorithm, *(f"{m:.2f} ± {s:.2f}" for m, s in stats), size]) + " |")
            native.append([algorithm, stats])
        lines += ["", f"Native runtime: {metadata['seconds']:.3f} s. Core + native: {r['core_seconds'] + metadata['seconds']:.3f} s "
                  "(sequential phases; compiler time and fault campaign excluded).", "",
                  "Timing is host-, version-, and harness-dependent. The original paper's timing protocol is not fully specified."]
    markdown = "\n".join(lines) + "\n"
    (out / "RESULTS.md").write_text(markdown)
    with (out / "faults.csv").open("w") as f:
        w = csv.writer(f); w.writerow(["family", "smoke", "core", "extended"]); w.writerows(faults)
    # Plotting is optional; numerical regeneration above uses only the stdlib.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})
        fig, ax = plt.subplots(1, 3, figsize=(15, 4.6), constrained_layout=True)
        ax[0].imshow(matrix, cmap="Blues", vmin=0, vmax=1)
        ax[0].set(xticks=range(4), yticks=range(4), xticklabels=names, yticklabels=names,
                  xlabel="Client", ylabel="Server", title=f"TLS compatibility · {len(r['tls'])} handshakes")
        for i in range(4):
            for j in range(4):
                ax[0].text(j, i, "accept" if matrix[i][j] else "reject", ha="center", va="center",
                           color="white" if matrix[i][j] else "#334155", fontsize=9)
        if faults:
            totals = [sum(x[i] for x in faults) for i in (1, 2, 3)]
            bars = ax[1].bar(["Smoke", "Core", "Extended"], totals, color=["#94a3b8", "#2563eb", "#0d9488"])
            ax[1].bar_label(bars, labels=[f"{x}/60" for x in totals], padding=4)
            ax[1].set(ylim=(0, 68), ylabel="Distinguished mutants", title="Reconstructed wrapper faults")
        if native:
            x = np.arange(3)
            for k, (op, color) in enumerate(zip(["KeyGen", "Encaps", "Decaps"], ["#94a3b8", "#2563eb", "#0d9488"])):
                ax[2].bar(x + (k-1)*.24, [z[1][k][0] for z in native], .24,
                          yerr=[z[1][k][1] for z in native], label=op, color=color, capsize=3)
            ax[2].set(xticks=x, xticklabels=["512", "768", "1024"], ylabel="µs per operation",
                      xlabel="ML-KEM parameter set", title="Native EVP · mean ± sample SD")
            ax[2].legend(frameon=False)
        fig.savefig(out / "results.png", dpi=180)
        fig.savefig(out / "results.pdf", metadata={"Creator": "PQCMorph", "CreationDate": None})
        plt.close(fig)
    except ImportError:
        print("Numerical report generated; matplotlib/numpy unavailable, plots omitted.")
    content = '<!doctype html><html lang="en"><meta charset="utf-8"><title>PQCMorph results</title>'
    content += '<meta name="viewport" content="width=device-width,initial-scale=1"><style>body{max-width:1200px;margin:40px auto;padding:0 24px;font-family:system-ui;color:#172033;background:#f8fafc;line-height:1.6}h1{font-size:34px;letter-spacing:-1px}h2{margin-top:36px;font-size:22px}img{width:100%;background:white;border:1px solid #e2e8f0;border-radius:8px}table{width:100%;border-collapse:collapse;font-size:14px;background:white}th,td{padding:10px 14px;border-bottom:1px solid #e2e8f0;text-align:left}th{background:#e2e8f0}.table-wrap{overflow:auto;border-radius:8px}p{max-width:100ch}</style>'
    content += '<h1>PQCMorph: measured reconstruction</h1><p>All values below are regenerated from the included observations.</p>'
    if (out / "results.png").exists():
        content += '<img src="results.png" alt="TLS, fault discrimination and native EVP results">'
    content += report_html(markdown) + '</html>'
    (out / "index.html").write_text(content)
    print(f"Report -> {out}/RESULTS.md")

if __name__ == "__main__":
    main()
