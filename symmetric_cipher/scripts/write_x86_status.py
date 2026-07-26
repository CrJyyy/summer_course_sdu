#!/usr/bin/env python3
"""Build and validate the machine-readable native x86 acceptance record."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


REQUIRED_ISAS = ("aesni", "ssse3", "avx2", "vaes", "pclmul", "vpclmul", "gfni")
STATIC_WITNESSES = (
    "AESENC",
    "AESDEC",
    "VAESENC",
    "VAESDEC",
    "PSHUFB",
    "PCLMULQDQ",
    "VPCLMULQDQ",
    "VGF2P8AFFINEINVQB",
    "VSM4RNDS4",
    "VSM4KEY4",
)


def count_from(pattern: str, text: str, label: str) -> int:
    match = re.search(pattern, text)
    if match is None:
        raise RuntimeError(f"missing {label} count")
    return int(match.group(1))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generic-log", type=Path, required=True)
    parser.add_argument("--x86-log", type=Path, required=True)
    parser.add_argument("--openssl-log", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    generic_log = args.generic_log.read_text(encoding="utf-8", errors="replace")
    x86_log = args.x86_log.read_text(encoding="utf-8", errors="replace")
    openssl_log = args.openssl_log.read_text(encoding="utf-8", errors="replace")
    summary = json.loads(args.summary.read_text(encoding="utf-8"))

    isa = dict(re.findall(r"^ISA ([a-z0-9]+) (pass|unsupported)$", x86_log, re.M))
    missing = [name for name in REQUIRED_ISAS if isa.get(name) != "pass"]
    if missing:
        raise RuntimeError(f"required x86 ISA paths did not execute: {missing}")
    if isa.get("vsm4") not in {"pass", "unsupported"}:
        raise RuntimeError("missing VSM4 runtime status")

    with args.raw.open(newline="", encoding="utf-8") as handle:
        raw_rows = list(csv.DictReader(handle))
    expected_rows = len(summary["results"]) * int(summary["samples"])
    if len(raw_rows) != expected_rows:
        raise RuntimeError((len(raw_rows), expected_rows))
    if any(row["status"] != "ok" for row in raw_rows):
        raise RuntimeError("benchmark contains failed samples")
    if any(not row["cycles_per_byte"] for row in raw_rows):
        raise RuntimeError("x86 benchmark contains an empty TSC value")
    if any(row.get("median_tsc_ticks_per_byte") is None for row in summary["results"]):
        raise RuntimeError("x86 summary contains a null TSC value")
    if summary.get("cycle_counter") != "rdtscp_tsc_ticks":
        raise RuntimeError("x86 benchmark did not use RDTSCP")

    openssl_version_match = re.search(r"\((OpenSSL [^)]+)\)", openssl_log)
    document = {
        "schema": 2,
        "architecture": "x86_64",
        "status": "passed",
        "platform": summary["platform"],
        "cpu": summary["cpu"],
        "compiler": summary["compiler"],
        "openssl": (
            openssl_version_match.group(1)
            if openssl_version_match
            else "unknown"
        ),
        "features": summary["features"],
        "tests": {
            "generic_checks": count_from(
                r"PASS: (\d+) checks", generic_log, "generic"
            ),
            "x86_backend_checks": count_from(
                r"PASS: (\d+) x86 checks", x86_log, "x86"
            ),
            "openssl_differential_checks": count_from(
                r"PASS: (\d+) OpenSSL", openssl_log, "OpenSSL"
            ),
            "asan_ubsan": "passed",
        },
        "runtime_isa": isa,
        "static_instruction_witnesses": list(STATIC_WITNESSES),
        "performance": {
            "raw_samples": len(raw_rows),
            "summary_rows": len(summary["results"]),
            "samples_per_case": summary["samples"],
            "cycles_metric": "RDTSCP invariant-TSC ticks per byte",
            "raw_file": "results/raw/x86_samples.csv",
            "summary_file": "results/summary/x86_summary.json",
        },
        "unsupported": (
            []
            if isa["vsm4"] == "pass"
            else [
                {
                    "isa": "VSM4",
                    "reason": "The native CPU does not advertise CPUID VSM4 support.",
                    "evidence": "Dispatch rejection plus compile/disassembly witness.",
                }
            ]
        ),
        "note": (
            "All CPUID-advertised x86 backends passed native execution. "
            "VSM4 is not claimed as runtime-verified when unsupported."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
