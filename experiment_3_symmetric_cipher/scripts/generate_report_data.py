#!/usr/bin/env python3
"""Turn benchmark JSON into a small LaTeX fragment used by the report."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "results" / "summary" / "native_summary.json"
X86_SOURCE = ROOT / "results" / "summary" / "x86_summary.json"
X86_STATUS = ROOT / "results" / "summary" / "x86_status.json"
OUTPUT = ROOT / "tmp" / "generated_results.tex"


def esc(value: str) -> str:
    return (
        value.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("&", r"\&")
        .replace("%", r"\%")
    )


def compiler_display(value: str) -> str:
    """Keep the PDF compact; the JSON still retains the exact compiler string."""
    if "msys2/MINGW-packages" in value:
        return value.split(" (", 1)[0] + " (MSYS2 UCRT64)"
    return value


with SOURCE.open(encoding="utf-8") as handle:
    doc = json.load(handle)

rows = doc["results"]
x86_doc = (
    json.loads(X86_SOURCE.read_text(encoding="utf-8"))
    if X86_SOURCE.exists()
    else None
)
x86_status = (
    json.loads(X86_STATUS.read_text(encoding="utf-8"))
    if X86_STATUS.exists()
    else None
)


def one(
    source_rows: list[dict],
    algorithm: str,
    backend: str,
    operation: str,
    size: int = 1_048_576,
) -> dict:
    matches = [
        row
        for row in source_rows
        if row["algorithm"] == algorithm
        and row["backend"] == backend
        and row["operation"] == operation
        and row["size_bytes"] == size
    ]
    if len(matches) != 1:
        raise RuntimeError((algorithm, backend, operation, size, len(matches)))
    return matches[0]


aes_ref = one(rows, "AES-128", "ref", "block")
aes_table = one(rows, "AES-128", "ttable-4k", "block")
aes_hw = one(rows, "AES-128", "aes-hw", "block")
sm4_ref = one(rows, "SM4-128", "ref", "block")
sm4_table = one(rows, "SM4-128", "ttable-4k", "block")
aes_gcm = one(rows, "AES-128", "aes-hw", "gcm")
sm4_gcm = one(rows, "SM4-128", "ref", "gcm")

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

if x86_doc is not None:
    x86_rows = x86_doc["results"]
    x86_selected = [
        row for row in x86_rows if row["size_bytes"] == 1_048_576
    ]
    lines.extend(
        [
            "% Generated from results/summary/x86_summary.json.",
            r"\newcommand{\XBenchAvailable}{1}",
            rf"\newcommand{{\XBenchCPU}}{{{esc(x86_doc['cpu'])}}}",
            rf"\newcommand{{\XBenchPlatform}}{{{esc(x86_doc['platform'])}}}",
            rf"\newcommand{{\XBenchCompiler}}{{{esc(compiler_display(x86_doc['compiler']))}}}",
            rf"\newcommand{{\XBenchCycleMetric}}{{{esc(x86_doc['cycle_counter'])}}}",
            r"\newcommand{\XOneMiBResultRows}{%",
        ]
    )
    for row in x86_selected:
        ticks = row["median_tsc_ticks_per_byte"]
        lines.append(
            rf"{esc(row['algorithm'])} & \texttt{{{esc(row['backend'])}}} & "
            rf"{esc(row['operation'])} & {row['median_gbps']:.3f} & "
            rf"{row['median_ns_per_byte']:.3f} & {ticks:.3f} \\"
        )
    lines.extend(["}", ""])
else:
    lines.extend(
        [
            r"\newcommand{\XBenchAvailable}{0}",
            r"\newcommand{\XBenchCPU}{pending}",
            r"\newcommand{\XBenchPlatform}{pending}",
            r"\newcommand{\XBenchCompiler}{pending}",
            r"\newcommand{\XBenchCycleMetric}{unavailable}",
            r"\newcommand{\XOneMiBResultRows}{}",
            "",
        ]
    )

if x86_status is not None:
    tests = x86_status["tests"]
    lines.extend(
        [
            rf"\newcommand{{\XGenericChecks}}{{{tests['generic_checks']}}}",
            rf"\newcommand{{\XBackendChecks}}{{{tests['x86_backend_checks']}}}",
            rf"\newcommand{{\XOpenSSLChecks}}{{{tests['openssl_differential_checks']}}}",
            rf"\newcommand{{\XOpenSSLVersion}}{{{esc(x86_status['openssl'])}}}",
            "",
        ]
    )
else:
    lines.extend(
        [
            r"\newcommand{\XGenericChecks}{0}",
            r"\newcommand{\XBackendChecks}{0}",
            r"\newcommand{\XOpenSSLChecks}{0}",
            r"\newcommand{\XOpenSSLVersion}{pending}",
            "",
        ]
    )

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {OUTPUT}")
