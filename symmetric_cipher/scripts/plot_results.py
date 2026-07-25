#!/usr/bin/env python3
"""Generate report figures directly from the machine-readable benchmark JSON."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "results" / "summary" / "native_summary.json"
OUT = ROOT / "results" / "figures"

COLORS = {
    "ref": "#4C78A8",
    "ttable-4k": "#F58518",
    "ttable-1k": "#ECA82C",
    "ttable-2k": "#B279A2",
    "shuffle": "#54A24B",
    "aes-hw": "#E45756",
}


def load_results() -> tuple[dict, list[dict]]:
    with INPUT.open(encoding="utf-8") as handle:
        document = json.load(handle)
    return document, document["results"]


def save(fig: plt.Figure, stem: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for suffix in ("pdf", "png"):
        fig.savefig(
            OUT / f"{stem}.{suffix}",
            dpi=300,
            bbox_inches="tight",
            facecolor="white",
        )
    plt.close(fig)


def plot_block_backends(document: dict, rows: list[dict]) -> None:
    selected = [
        row
        for row in rows
        if row["operation"] == "block" and row["size_bytes"] == 1_048_576
    ]
    selected.sort(key=lambda row: row["median_gbps"])
    labels = [f'{r["algorithm"]} / {r["backend"]}' for r in selected]
    values = [r["median_gbps"] for r in selected]
    colors = [COLORS.get(r["backend"], "#72B7B2") for r in selected]

    fig, ax = plt.subplots(figsize=(8.4, 5.8), constrained_layout=True)
    bars = ax.barh(labels, values, color=colors, edgecolor="#333333", linewidth=0.5)
    ax.set_xscale("log")
    ax.set_xlabel("Median throughput (GB/s, logarithmic scale)")
    ax.set_title("Block-encryption backends, 1 MiB")
    ax.grid(axis="x", alpha=0.25, which="both")
    for bar, value in zip(bars, values):
        ax.text(
            value * 1.04,
            bar.get_y() + bar.get_height() / 2,
            f"{value:.3f}",
            va="center",
            fontsize=8,
        )
    ax.text(
        0,
        -0.14,
        f'Source: native_summary.json; {document["cpu"]}; '
        "3 warmups, 15 samples; key setup excluded.",
        transform=ax.transAxes,
        fontsize=8,
        color="#555555",
    )
    save(fig, "block_backends_1m")


def plot_size_scaling(document: dict, rows: list[dict]) -> None:
    wanted = {
        ("AES-128", "ref"),
        ("AES-128", "ttable-4k"),
        ("AES-128", "aes-hw"),
        ("SM4-128", "ref"),
        ("SM4-128", "ttable-4k"),
        ("SM4-128", "ttable-1k"),
        ("SM4-128", "ttable-2k"),
        ("SM4-128", "shuffle"),
    }
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True, constrained_layout=True)
    for ax, algorithm in zip(axes, ("AES-128", "SM4-128")):
        for pair in sorted(wanted):
            if pair[0] != algorithm:
                continue
            series = [
                r
                for r in rows
                if r["operation"] == "block"
                and (r["algorithm"], r["backend"]) == pair
            ]
            series.sort(key=lambda r: r["size_bytes"])
            ax.plot(
                [r["size_bytes"] for r in series],
                [r["median_gbps"] for r in series],
                marker="o",
                linewidth=1.8,
                markersize=4,
                label=pair[1],
                color=COLORS.get(pair[1], "#72B7B2"),
            )
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_title(algorithm)
        ax.set_xlabel("Message size (bytes)")
        ax.grid(True, alpha=0.25, which="both")
        ax.legend(fontsize=8)
    axes[0].set_ylabel("Median throughput (GB/s, logarithmic scale)")
    fig.suptitle("Throughput versus message size")
    fig.text(
        0.01,
        -0.03,
        f'Source: native_summary.json; {document["cpu"]}; '
        "error bars are reported separately as IQR in JSON.",
        fontsize=8,
        color="#555555",
    )
    save(fig, "size_scaling")


def plot_modes(document: dict, rows: list[dict]) -> None:
    selected = [
        r
        for r in rows
        if r["size_bytes"] in (512, 4096)
        and r["operation"] in ("ctr", "gcm", "xts", "xts-ieee", "xts-gb")
    ]
    labels = sorted({f'{r["algorithm"]} {r["operation"]}' for r in selected})
    by_label_size = {
        (f'{r["algorithm"]} {r["operation"]}', r["size_bytes"]): r["median_gbps"]
        for r in selected
    }
    y = list(range(len(labels)))
    fig, ax = plt.subplots(figsize=(8.4, 5.0), constrained_layout=True)
    ax.barh(
        [p - 0.19 for p in y],
        [by_label_size.get((label, 512), 0) for label in labels],
        height=0.36,
        label="512 B",
        color="#4C78A8",
        edgecolor="#333333",
        linewidth=0.4,
    )
    ax.barh(
        [p + 0.19 for p in y],
        [by_label_size.get((label, 4096), 0) for label in labels],
        height=0.36,
        label="4 KiB",
        color="#F58518",
        edgecolor="#333333",
        linewidth=0.4,
    )
    ax.set_yticks(y, labels)
    ax.set_xscale("log")
    ax.set_xlabel("Median throughput (GB/s, logarithmic scale)")
    ax.set_title("CTR, GCM and XTS mode throughput")
    ax.grid(axis="x", alpha=0.25, which="both")
    ax.legend()
    ax.text(
        0,
        -0.14,
        f'Source: native_summary.json; {document["cpu"]}; '
        "XTS includes tweak generation and ciphertext-stealing-capable path.",
        transform=ax.transAxes,
        fontsize=8,
        color="#555555",
    )
    save(fig, "mode_throughput")


def main() -> None:
    document, rows = load_results()
    plot_block_backends(document, rows)
    plot_size_scaling(document, rows)
    plot_modes(document, rows)
    print(f"Wrote figures to {OUT}")


if __name__ == "__main__":
    main()
