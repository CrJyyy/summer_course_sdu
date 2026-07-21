#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
REPO = WORK / "secp256k1"
SOURCES = WORK / "sources"
BUILDS = WORK / "builds"
RESULTS = ROOT / "results"
RAW = RESULTS / "raw"
DIFFS = RESULTS / "diffs"
REPOSITORY_URL = "https://github.com/bitcoin-core/secp256k1.git"
TAGS = ["v0.3.0", "v0.3.1", "v0.3.2", "v0.4.0", "v0.4.1", "v0.5.0", "v0.5.1", "v0.7.1"]
SECURITY_TEST_CONFIGS = [
    ("v0.3.0", "default", ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5"]),
    ("v0.3.1", "default", ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5"]),
    ("v0.3.2", "default", ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5"]),
]
BENCHMARK_CONFIGS = [
    ("v0.4.1", "default", []),
    ("v0.5.0", "table2k", ["-DSECP256K1_ECMULT_GEN_KB=2"]),
    ("v0.5.0", "table22k", ["-DSECP256K1_ECMULT_GEN_KB=22"]),
    ("v0.5.0", "table86k", ["-DSECP256K1_ECMULT_GEN_KB=86"]),
]
BENCHMARK_KEYS = {(tag, variant) for tag, variant, _ in BENCHMARK_CONFIGS}


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), file=sys.stderr)
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def executable(name: str) -> str:
    found = shutil.which(name)
    if not found:
        sibling = Path(sys.executable).parent / name
        if sibling.is_file() and os.access(sibling, os.X_OK):
            found = str(sibling)
    if not found:
        raise RuntimeError(f"required executable not found: {name}")
    return found


def ensure_repo() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    if not REPO.exists():
        run([executable("git"), "clone", "--filter=blob:none", "--no-checkout", REPOSITORY_URL, str(REPO)])
    for tag in TAGS:
        present = subprocess.run(
            [executable("git"), "rev-parse", "--quiet", "--verify", f"refs/tags/{tag}"],
            cwd=REPO,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not present:
            run(
                [executable("git"), "fetch", "--force", "--depth=1", "origin", f"refs/tags/{tag}:refs/tags/{tag}"],
                cwd=REPO,
            )
    SOURCES.mkdir(parents=True, exist_ok=True)
    for tag in TAGS:
        target = SOURCES / tag
        if not target.exists():
            run([executable("git"), "worktree", "add", "--detach", str(target), tag], cwd=REPO)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def command_output(command: list[str]) -> str:
    return run(command).stdout.strip()


def run_and_log(command: list[str], log_path: Path) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = run(command)
    except subprocess.CalledProcessError as error:
        log_path.write_text(error.stdout or "", encoding="utf-8")
        raise
    log_path.write_text(completed.stdout, encoding="utf-8")
    return completed


def collect_metadata() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    metadata: list[dict[str, str]] = []
    for tag in TAGS:
        commit = run(["git", "rev-list", "-n", "1", tag], cwd=REPO).stdout.strip()
        date = run(["git", "show", "-s", "--format=%cI", commit], cwd=REPO).stdout.strip()
        subject = run(["git", "show", "-s", "--format=%s", commit], cwd=REPO).stdout.strip()
        metadata.append({"tag": tag, "commit": commit, "commit_date": date, "subject": subject})
    write_json(RESULTS / "tag_commits.json", metadata)
    with (RESULTS / "tag_commits.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["tag", "commit", "commit_date", "subject"])
        writer.writeheader()
        writer.writerows(metadata)
    environment = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version,
        "clang": command_output([executable("clang"), "--version"]),
        "cmake": command_output([executable("cmake"), "--version"]),
        "ninja": command_output([executable("ninja"), "--version"]),
        "benchmark_note": "Apple ARM64 measurements do not reproduce x86_64/GCC-specific upstream claims.",
    }
    write_json(RESULTS / "environment.json", environment)
    DIFFS.mkdir(parents=True, exist_ok=True)
    intervals = [
        ("v0.3.0", "v0.3.1", "clang14_constant_time"),
        ("v0.3.1", "v0.3.2", "gcc13_ecdh_constant_time"),
        ("v0.4.0", "v0.4.1", "x86_assembly_removal"),
        ("v0.4.1", "v0.5.0", "ecmult_gen_rework"),
        ("v0.5.0", "v0.5.1", "default_table_86k"),
    ]
    for old, new, stem in intervals:
        log = run(["git", "log", "--oneline", "--no-decorate", f"{old}..{new}"], cwd=REPO).stdout
        diffstat = run(["git", "diff", "--stat", old, new], cwd=REPO).stdout
        (DIFFS / f"{stem}_log.txt").write_text(log, encoding="utf-8")
        (DIFFS / f"{stem}_diffstat.txt").write_text(diffstat, encoding="utf-8")


def configure_and_build(tag: str, variant: str, extra: list[str]) -> Path:
    source = SOURCES / tag
    build = BUILDS / f"{tag}-{variant}"
    build.mkdir(parents=True, exist_ok=True)
    command = [
        executable("cmake"),
        "-S",
        str(source),
        "-B",
        str(build),
        "-G",
        "Ninja",
        f"-DCMAKE_MAKE_PROGRAM={executable('ninja')}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=clang",
        "-DSECP256K1_BUILD_TESTS=ON",
        f"-DSECP256K1_BUILD_BENCHMARK={'ON' if (tag, variant) in BENCHMARK_KEYS else 'OFF'}",
        *extra,
    ]
    RAW.mkdir(parents=True, exist_ok=True)
    run_and_log(command, RAW / f"configure_{tag}_{variant}.txt")
    run_and_log(
        [executable("cmake"), "--build", str(build), "--parallel"],
        RAW / f"build_{tag}_{variant}.txt",
    )
    run_and_log(
        [executable("ctest"), "--test-dir", str(build), "--output-on-failure"],
        RAW / f"ctest_{tag}_{variant}.txt",
    )
    return build


def find_benchmark(build: Path) -> Path:
    candidates = [path for path in build.rglob("bench") if path.is_file() and os.access(path, os.X_OK)]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one bench executable under {build}, found {candidates}")
    return candidates[0]


def find_library_artifact(build: Path) -> Path:
    candidates = [
        path
        for path in build.rglob("libsecp256k1*")
        if path.is_file()
        and not path.is_symlink()
        and (".dylib" in path.name or ".so" in path.name or path.suffix == ".dll")
    ]
    if not candidates:
        candidates = [
            path
            for path in build.rglob("libsecp256k1*.a")
            if path.is_file() and not path.is_symlink()
        ]
    if not candidates:
        raise RuntimeError(f"could not find a libsecp256k1 library artifact under {build}")
    return max(candidates, key=lambda path: path.stat().st_size)


def collect_library_sizes(builds: list[tuple[str, str, Path]]) -> None:
    table_sizes: dict[str, int | str] = {
        "default": "version default",
        "table2k": 2,
        "table22k": 22,
        "table86k": 86,
    }
    rows: list[dict[str, Any]] = []
    for tag, variant, build in builds:
        artifact = find_library_artifact(build)
        size = artifact.stat().st_size
        rows.append(
            {
                "tag": tag,
                "variant": variant,
                "ecmult_gen_table_kib": table_sizes.get(variant, "unknown"),
                "library_artifact": str(artifact.relative_to(ROOT)),
                "library_bytes": size,
                "library_kib": round(size / 1024, 4),
            }
        )
    with (RESULTS / "library_sizes.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    write_json(RESULTS / "library_sizes.json", rows)


BENCH_ROW_PIPE = re.compile(
    r"^\s*ecdsa_sign\s*\|\s*([0-9.]+)\s*(ns|us|ms)\s*/\s*sig\s*\|",
    re.MULTILINE,
)
BENCH_ROW_COMMA = re.compile(
    r"^\s*ecdsa_sign\s*,\s*([0-9.]+)\s*,\s*([0-9.]+)\s*,\s*([0-9.]+)",
    re.MULTILINE,
)


def parse_microseconds(output: str) -> float:
    comma_match = BENCH_ROW_COMMA.search(output)
    if comma_match:
        return float(comma_match.group(2))
    pipe_match = BENCH_ROW_PIPE.search(output)
    if pipe_match:
        value = float(pipe_match.group(1))
        unit = pipe_match.group(2)
        return value * {"ns": 0.001, "us": 1.0, "ms": 1000.0}[unit]
    raise RuntimeError(f"could not parse ecdsa_sign benchmark row:\n{output}")


def benchmark(builds: list[tuple[str, str, Path]], warmups: int, runs: int) -> None:
    rows: list[dict[str, Any]] = []
    for tag, variant, build in builds:
        bench = find_benchmark(build)
        environment = os.environ.copy()
        environment["SECP256K1_BENCH_ITERS"] = "20000"
        for _ in range(warmups):
            run([str(bench), "ecdsa_sign"], env=environment)
        for index in range(runs):
            started = time.perf_counter()
            completed = run([str(bench), "ecdsa_sign"], env=environment)
            wall_seconds = time.perf_counter() - started
            output_path = RAW / f"bench_{tag}_{variant}_{index + 1:02d}.txt"
            output_path.write_text(completed.stdout, encoding="utf-8")
            microseconds = parse_microseconds(completed.stdout)
            rows.append(
                {
                    "tag": tag,
                    "variant": variant,
                    "run": index + 1,
                    "microseconds_per_signature": microseconds,
                    "operations_per_second": 1_000_000.0 / microseconds,
                    "wall_seconds": wall_seconds,
                    "benchmark_binary_bytes": bench.stat().st_size,
                }
            )
    with (RESULTS / "benchmark_runs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summaries: list[dict[str, Any]] = []
    for tag, variant, _ in builds:
        group = [row for row in rows if row["tag"] == tag and row["variant"] == variant]
        values = [float(row["microseconds_per_signature"]) for row in group]
        quartiles = statistics.quantiles(values, n=4, method="inclusive")
        median_us = statistics.median(values)
        summaries.append(
            {
                "tag": tag,
                "variant": variant,
                "runs": len(values),
                "median_microseconds_per_signature": median_us,
                "q1_microseconds": quartiles[0],
                "q3_microseconds": quartiles[2],
                "iqr_microseconds": quartiles[2] - quartiles[0],
                "median_operations_per_second": 1_000_000.0 / median_us,
                "benchmark_binary_bytes": group[0]["benchmark_binary_bytes"],
            }
        )
    with (RESULTS / "benchmark_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)
    write_json(RESULTS / "benchmark_summary.json", summaries)


def select_benchmark_builds(
    builds: list[tuple[str, str, Path]],
) -> list[tuple[str, str, Path]]:
    selected = [build for build in builds if (build[0], build[1]) in BENCHMARK_KEYS]
    if len(selected) != len(BENCHMARK_CONFIGS):
        found = {(tag, variant) for tag, variant, _ in selected}
        missing = sorted(BENCHMARK_KEYS - found)
        raise RuntimeError(f"benchmark build(s) missing from build matrix: {missing}")
    return selected


def load_build_matrix() -> list[tuple[str, str, Path]]:
    matrix_path = RESULTS / "build_matrix.json"
    if not matrix_path.exists():
        raise RuntimeError("build matrix not found; run --case build or --case all first")
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    return [(row["tag"], row["variant"], Path(row["build"])) for row in matrix]


def run_builds() -> list[tuple[str, str, Path]]:
    configurations = SECURITY_TEST_CONFIGS + BENCHMARK_CONFIGS
    builds = [
        (tag, variant, configure_and_build(tag, variant, extra))
        for tag, variant, extra in configurations
    ]
    write_json(
        RESULTS / "build_matrix.json",
        [
            {
                "tag": tag,
                "variant": variant,
                "purpose": "performance_benchmark" if (tag, variant) in BENCHMARK_KEYS else "security_build_test",
                "benchmark_enabled": (tag, variant) in BENCHMARK_KEYS,
                "official_tests_passed": True,
                "ctest_log": str((RAW / f"ctest_{tag}_{variant}.txt").relative_to(ROOT)),
                "build": str(build),
            }
            for tag, variant, build in builds
        ],
    )
    return builds


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce libsecp256k1 tag, test, and benchmark evidence")
    parser.add_argument("--case", choices=["metadata", "build", "sizes", "benchmark", "all"], default="all")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=2)
    args = parser.parse_args()
    if args.case == "sizes":
        collect_library_sizes(select_benchmark_builds(load_build_matrix()))
        return
    ensure_repo()
    collect_metadata()
    if args.case == "metadata":
        return
    if args.case in {"build", "all"}:
        builds = run_builds()
    else:
        builds = load_build_matrix()
    benchmark_builds = select_benchmark_builds(builds)
    collect_library_sizes(benchmark_builds)
    if args.case in {"benchmark", "all"}:
        benchmark(benchmark_builds, args.warmups, args.runs)


if __name__ == "__main__":
    main()
