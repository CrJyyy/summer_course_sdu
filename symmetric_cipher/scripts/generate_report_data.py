#!/usr/bin/env python3
"""Turn benchmark JSON into a small LaTeX fragment used by the report."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "results" / "summary" / "native_summary.json"
OUTPUT = ROOT / "tmp" / "generated_results.tex"


def esc(value: str) -> str:
    return (
        value.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("&", r"\&")
        .replace("%", r"\%")
    )


with SOURCE.open(encoding="utf-8") as handle:
    doc = json.load(handle)

rows = doc["results"]


def one(algorithm: str, backend: str, operation: str, size: int = 1_048_576) -> dict:
    matches = [
        row
        for row in rows
        if row["algorithm"] == algorithm
        and row["backend"] == backend
        and row["operation"] == operation
        and row["size_bytes"] == size
    ]
    if len(matches) != 1:
        raise RuntimeError((algorithm, backend, operation, size, len(matches)))
    return matches[0]


aes_ref = one("AES-128", "ref", "block")
aes_table = one("AES-128", "ttable-4k", "block")
aes_hw = one("AES-128", "aes-hw", "block")
sm4_ref = one("SM4-128", "ref", "block")
sm4_table = one("SM4-128", "ttable-4k", "block")
aes_gcm = one("AES-128", "aes-hw", "gcm")
sm4_gcm = one("SM4-128", "ref", "gcm")

selected = [
    row
    for row in rows
    if row["size_bytes"] == 1_048_576
]

lines = [
    "% Generated from results/summary/native_summary.json; do not hand-edit.",
    rf"\newcommand{{\BenchCPU}}{{{esc(doc['cpu'])}}}",
    rf"\newcommand{{\BenchPlatform}}{{{esc(doc['platform'])}}}",
    rf"\newcommand{{\BenchCompiler}}{{{esc(doc['compiler'])}}}",
    rf"\newcommand{{\AESRefGbps}}{{{aes_ref['median_gbps']:.3f}}}",
    rf"\newcommand{{\AESTableGbps}}{{{aes_table['median_gbps']:.3f}}}",
    rf"\newcommand{{\AESHWGbps}}{{{aes_hw['median_gbps']:.3f}}}",
    rf"\newcommand{{\AESHWGain}}{{{aes_hw['median_gbps']/aes_ref['median_gbps']:.2f}}}",
    rf"\newcommand{{\AESTableGain}}{{{aes_table['median_gbps']/aes_ref['median_gbps']:.2f}}}",
    rf"\newcommand{{\SMFourRefGbps}}{{{sm4_ref['median_gbps']:.3f}}}",
    rf"\newcommand{{\SMFourTableGbps}}{{{sm4_table['median_gbps']:.3f}}}",
    rf"\newcommand{{\SMFourTableGain}}{{{sm4_table['median_gbps']/sm4_ref['median_gbps']:.2f}}}",
    rf"\newcommand{{\AESGCMGbps}}{{{aes_gcm['median_gbps']:.3f}}}",
    rf"\newcommand{{\SMFourGCMGbps}}{{{sm4_gcm['median_gbps']:.3f}}}",
    r"\newcommand{\OneMiBResultRows}{%",
]
for row in selected:
    lines.append(
        rf"{esc(row['algorithm'])} & \texttt{{{esc(row['backend'])}}} & "
        rf"{esc(row['operation'])} & {row['median_gbps']:.3f} & "
        rf"{row['median_ns_per_byte']:.3f} & {row['iqr_ns_per_byte']:.3f} \\"
    )
lines.extend(["}", ""])

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {OUTPUT}")
