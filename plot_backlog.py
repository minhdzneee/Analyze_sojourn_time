#!/usr/bin/env python3
"""
Plot backlog from repeated `tc -s -d class show dev ifb0` output.

The active window is chosen from the class 1:1 packet counter:
- start: first snapshot where class 1:1 packet counter increases
- end: last snapshot where class 1:1 packet counter increases

This intentionally ignores later snapshots where class 1:3 may continue to grow
because they are outside the priority flow's active interval.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import shlex
from dataclasses import dataclass, field
from statistics import fmean, median, stdev


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
TIME_RE = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})$")
CLASS_RE = re.compile(r"^class\s+\S+\s+(\S+)")
SENT_RE = re.compile(
    r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+"
    r"\(dropped\s+(\d+),\s+overlimits\s+(\d+)\s+requeues\s+(\d+)\)"
)
BACKLOG_RE = re.compile(r"backlog\s+(\S+)\s+(\d+)p\s+requeues\s+(\d+)")


@dataclass
class ClassStats:
    sent_bytes: int = 0
    sent_pkt: int = 0
    dropped: int = 0
    overlimits: int = 0
    sent_requeues: int = 0
    backlog_raw: str = "0b"
    backlog_bytes: float | None = 0.0
    backlog_pkt: int = 0
    backlog_requeues: int = 0


@dataclass
class Snapshot:
    index: int
    clock: str
    clock_s: int
    elapsed_s: int = 0
    classes: dict[str, ClassStats] = field(default_factory=dict)


def strip_ansi(line: str) -> str:
    return ANSI_RE.sub("", line).strip()


def parse_clock_s(clock: str) -> int:
    m = TIME_RE.match(clock)
    if not m:
        raise ValueError(f"invalid clock: {clock}")
    h, minute, second = (int(x) for x in m.groups())
    return h * 3600 + minute * 60 + second


def parse_size_to_bytes(raw: str) -> float | None:
    """Best-effort parser for tc size strings such as 0b, 1514b, 12Kb."""
    m = re.match(r"^([0-9.]+)([A-Za-z]*)$", raw)
    if not m:
        return None

    value = float(m.group(1))
    unit = m.group(2)
    multipliers = {
        "": 1,
        "b": 1,
        "B": 1,
        "Kb": 1024,
        "KB": 1024,
        "Mb": 1024 * 1024,
        "MB": 1024 * 1024,
        "Gb": 1024 * 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
    }
    return value * multipliers.get(unit, 1)


def parse_backlog_file(path: str) -> list[Snapshot]:
    snapshots: list[Snapshot] = []
    current: Snapshot | None = None
    current_class: str | None = None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = strip_ansi(raw_line)
            if not line:
                continue

            if TIME_RE.match(line):
                if current is not None and current.classes:
                    snapshots.append(current)
                current = Snapshot(
                    index=len(snapshots),
                    clock=line,
                    clock_s=parse_clock_s(line),
                )
                current_class = None
                continue

            if current is None:
                continue

            m = CLASS_RE.match(line)
            if m:
                current_class = m.group(1)
                current.classes.setdefault(current_class, ClassStats())
                continue

            if current_class is None:
                continue

            m = SENT_RE.search(line)
            if m:
                stats = current.classes[current_class]
                (
                    sent_bytes,
                    sent_pkt,
                    dropped,
                    overlimits,
                    sent_requeues,
                ) = (int(x) for x in m.groups())
                stats.sent_bytes = sent_bytes
                stats.sent_pkt = sent_pkt
                stats.dropped = dropped
                stats.overlimits = overlimits
                stats.sent_requeues = sent_requeues
                continue

            m = BACKLOG_RE.search(line)
            if m:
                stats = current.classes[current_class]
                backlog_raw, backlog_pkt, backlog_requeues = m.groups()
                stats.backlog_raw = backlog_raw
                stats.backlog_bytes = parse_size_to_bytes(backlog_raw)
                stats.backlog_pkt = int(backlog_pkt)
                stats.backlog_requeues = int(backlog_requeues)

    if current is not None and current.classes:
        snapshots.append(current)

    normalize_elapsed_time(snapshots)
    return snapshots


def normalize_elapsed_time(snapshots: list[Snapshot]) -> None:
    if not snapshots:
        return

    offset = 0
    prev_abs = snapshots[0].clock_s
    first_abs = snapshots[0].clock_s

    for snap in snapshots:
        abs_s = snap.clock_s + offset
        if abs_s < prev_abs:
            offset += 24 * 3600
            abs_s = snap.clock_s + offset
        snap.elapsed_s = abs_s - first_abs
        prev_abs = abs_s


def packet_counts(snapshots: list[Snapshot], class_id: str) -> list[int | None]:
    values: list[int | None] = []
    for snap in snapshots:
        stats = snap.classes.get(class_id)
        values.append(stats.sent_pkt if stats is not None else None)
    return values


def packet_deltas(values: list[int | None]) -> list[int]:
    deltas = [0 for _ in values]
    for i in range(1, len(values)):
        prev = values[i - 1]
        cur = values[i]
        if prev is None or cur is None:
            continue
        delta = cur - prev
        if delta > 0:
            deltas[i] = delta
        elif delta < 0 and cur > 0:
            # Counter reset during capture. Treat current value as new-run traffic.
            deltas[i] = cur

    if len(values) > 1 and values[0] is not None and values[1] is not None:
        first_delta = values[1] - values[0]
        if first_delta > 0:
            deltas[0] = first_delta

    return deltas


def find_active_window(
    snapshots: list[Snapshot],
    active_class: str,
    include_stop_sample: bool = False,
) -> tuple[int, int, list[int]]:
    values = packet_counts(snapshots, active_class)
    deltas = packet_deltas(values)
    active_indices = [i for i, delta in enumerate(deltas) if delta > 0]

    if not active_indices:
        raise ValueError(f"class {active_class} never increases in this file")

    start = active_indices[0]
    end = active_indices[-1]
    if include_stop_sample and end + 1 < len(snapshots):
        end += 1

    return start, end, deltas


def percentile(values: list[float], q: float) -> float:
    if not values:
        return math.nan

    sorted_values = sorted(values)
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] * (hi - pos) + sorted_values[hi] * (pos - lo)


def moving_average(values: list[float], window: int) -> list[float]:
    if not values:
        return []

    if window <= 1:
        return values[:]

    window = max(1, window)
    out: list[float] = []
    running_sum = 0.0
    queue: list[float] = []

    for value in values:
        queue.append(value)
        running_sum += value
        if len(queue) > window:
            running_sum -= queue.pop(0)
        out.append(running_sum / len(queue))

    return out


def summarize_window(
    snapshots: list[Snapshot],
    start: int,
    end: int,
    classes: list[str],
) -> dict[str, dict[str, float]]:
    summary: dict[str, dict[str, float]] = {}
    window = snapshots[start : end + 1]

    for class_id in classes:
        backlog_pkts = [
            snap.classes[class_id].backlog_pkt
            for snap in window
            if class_id in snap.classes
        ]
        sent_values = packet_counts(snapshots, class_id)
        deltas = packet_deltas(sent_values)
        nonzero = [x for x in backlog_pkts if x > 0]

        summary[class_id] = {
            "samples": len(backlog_pkts),
            "avg_backlog_p": fmean(backlog_pkts) if backlog_pkts else math.nan,
            "median_backlog_p": median(backlog_pkts) if backlog_pkts else math.nan,
            "avg_backlog_p_nonzero": fmean(nonzero) if nonzero else 0.0,
            "max_backlog_p": max(backlog_pkts) if backlog_pkts else math.nan,
            "p95_backlog_p": percentile([float(x) for x in backlog_pkts], 0.95),
            "std_backlog_p": stdev(backlog_pkts) if len(backlog_pkts) > 1 else 0.0,
            "nonzero_samples": len(nonzero),
            "sent_delta_pkt": sum(deltas[start : end + 1]),
        }

    return summary


def write_active_csv(
    path: str,
    snapshots: list[Snapshot],
    start: int,
    end: int,
    classes: list[str],
) -> None:
    rows = []
    for rel_idx, snap in enumerate(snapshots[start : end + 1]):
        for class_id in classes:
            stats = snap.classes.get(class_id)
            if stats is None:
                continue
            rows.append(
                {
                    "sample": rel_idx,
                    "source_index": snap.index,
                    "clock": snap.clock,
                    "elapsed_s": snap.elapsed_s - snapshots[start].elapsed_s,
                    "class": class_id,
                    "sent_bytes": stats.sent_bytes,
                    "sent_pkt": stats.sent_pkt,
                    "dropped": stats.dropped,
                    "overlimits": stats.overlimits,
                    "backlog_raw": stats.backlog_raw,
                    "backlog_bytes": stats.backlog_bytes,
                    "backlog_pkt": stats.backlog_pkt,
                    "requeues": stats.backlog_requeues,
                }
            )

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)


def plot_backlog(
    out_path: str,
    source_path: str,
    snapshots: list[Snapshot],
    start: int,
    end: int,
    classes: list[str],
    x_axis: str,
    metric: str,
    active_class: str,
    summary: dict[str, dict[str, float]],
    window_size: int,
) -> bool:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"  ! matplotlib not available, skipped PNG: {exc}")
        return False

    window = snapshots[start : end + 1]
    if x_axis == "time":
        x_values = [snap.elapsed_s - snapshots[start].elapsed_s for snap in window]
        x_label = "Elapsed Time in Active Window (s)"
        axis_info = "Elapsed time"
    else:
        x_values = list(range(len(window)))
        x_label = "Sample Index"
        axis_info = "Sample index"

    value_attr = "backlog_pkt" if metric == "packets" else "backlog_bytes"
    y_label = "Backlog (packets)" if metric == "packets" else "Backlog (bytes)"

    fig, ax = plt.subplots(figsize=(16, 6))
    colors = {
        "1:1": "#1E88E5",
        "1:2": "#43A047",
        "1:3": "#FB8C00",
    }

    fig.patch.set_facecolor("white")
    fig.suptitle(
        f"Backlog Trend | class {' vs class '.join(classes)} | Active: class {active_class} | X: {axis_info}",
        fontsize=13,
        fontweight="bold",
        y=0.99,
    )

    ax.set_facecolor("white")
    plot_order = [active_class] + [class_id for class_id in classes if class_id != active_class]

    for class_id in plot_order:
        y_values = []
        for snap in window:
            stats = snap.classes.get(class_id)
            if stats is None:
                y_values.append(math.nan)
            else:
                value = getattr(stats, value_attr)
                y_values.append(float(value) if value is not None else math.nan)

        if window_size <= 0:
            plot_values = y_values
            line_kind = "Raw"
        else:
            plot_values = moving_average(y_values, window_size)
            line_kind = "Moving Avg"

        is_active = class_id == active_class
        label = f"class {class_id} Backlog {line_kind}" + (" ★ Active" if is_active else "")
        ax.plot(
            x_values,
            plot_values,
            label=label,
            color=colors.get(class_id),
            linewidth=2.2 if is_active else 1.3,
            alpha=1.0 if is_active else 0.75,
        )

    window_info = "Raw samples" if window_size <= 0 else f"Window={window_size} samples"
    ax.set_title(
        f"Backlog Scenario — {os.path.basename(source_path)} ({window_info}, X={axis_info})",
        fontsize=11,
        pad=6,
    )
    ax.set_xlabel(x_label, fontsize=10)
    ax.set_ylabel(y_label, fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.4, color="gray")
    ax.tick_params(labelsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=9, loc="upper left")

    ax.annotate(
        f"★ Active Window Reference: class {active_class}",
        xy=(0.0, 1.01),
        xycoords="axes fraction",
        ha="left",
        va="bottom",
        fontsize=8.5,
        color=colors.get(active_class, "#1E88E5"),
        fontweight="bold",
    )

    for idx, class_id in enumerate(plot_order):
        stats = summary.get(class_id)
        if not stats:
            continue

        text = (
            f"class {class_id} (n={int(stats['samples']):,})\n"
            f"Mean {stats['avg_backlog_p']:.2f} Med {stats['median_backlog_p']:.2f}\n"
            f"Max {stats['max_backlog_p']:.2f} Std {stats['std_backlog_p']:.2f}\n"
            f"SentΔ {int(stats['sent_delta_pkt']):,} Nonzero {int(stats['nonzero_samples']):,}"
        )
        ax.text(
            0.78,
            0.99 - idx * 0.31,
            text,
            transform=ax.transAxes,
            fontsize=7.5,
            verticalalignment="top",
            fontfamily="monospace",
            linespacing=1.4,
            bbox=dict(
                boxstyle="round,pad=0.3",
                facecolor="white",
                edgecolor=colors.get(class_id),
                linewidth=1.2,
                alpha=0.90,
            ),
            color=colors.get(class_id),
        )

    plt.tight_layout(pad=2.5)
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f" ✔ Plot saved: {out_path}")
    return True


def default_out_paths(input_path: str, out_dir: str | None, window_size: int) -> tuple[str, str]:
    base = os.path.splitext(os.path.basename(input_path))[0]
    parent_dir = out_dir or os.path.dirname(os.path.abspath(input_path)) or "."
    target_dir = os.path.join(parent_dir, f"output_{base}")
    os.makedirs(target_dir, exist_ok=True)
    plot_suffix = "raw" if window_size <= 0 else f"w{window_size}"
    return (
        os.path.join(target_dir, f"{base}_active_backlog.csv"),
        os.path.join(target_dir, f"{base}_active_backlog_{plot_suffix}.png"),
    )


def analyze_one(args: argparse.Namespace, input_path: str) -> None:
    if not os.path.isfile(input_path):
        print(f"\n{input_path}: file not found, skipped")
        return

    snapshots = parse_backlog_file(input_path)
    if not snapshots:
        print(f"\n{input_path}: no snapshots parsed")
        return

    start, end, active_deltas = find_active_window(
        snapshots,
        args.active_class,
        include_stop_sample=args.include_stop_sample,
    )
    classes = args.classes
    summary = summarize_window(snapshots, start, end, classes)
    csv_path, png_path = default_out_paths(input_path, args.out_dir, args.window)

    write_active_csv(csv_path, snapshots, start, end, classes)
    plotted = plot_backlog(
        png_path,
        input_path,
        snapshots,
        start,
        end,
        classes,
        args.x_axis,
        args.metric,
        args.active_class,
        summary,
        args.window,
    )

    active_pkt_delta = sum(active_deltas[start : end + 1])
    print(f"\n{input_path}")
    print(f"  snapshots parsed : {len(snapshots):,}")
    print(
        "  active window    : "
        f"index {start:,} -> {end:,} "
        f"({snapshots[start].clock} -> {snapshots[end].clock})"
    )
    if args.window <= 0:
        print("  plot mode        : raw line graph (no moving average)")
    else:
        print(f"  plot mode        : moving average window {args.window:,} samples")
    print(f"  {args.active_class} delta : {active_pkt_delta:,} packets")
    print(f"  exported CSV     : {csv_path}")
    if plotted:
        print(f"  exported PNG     : {png_path}")

    for class_id, stats in summary.items():
        print(
            f"  class {class_id}: "
            f"avg={stats['avg_backlog_p']:.2f}p, "
            f"avg_nonzero={stats['avg_backlog_p_nonzero']:.2f}p, "
            f"p95={stats['p95_backlog_p']:.2f}p, "
            f"max={stats['max_backlog_p']:.0f}p, "
            f"nonzero={int(stats['nonzero_samples'])}/{int(stats['samples'])}, "
            f"sent_delta={int(stats['sent_delta_pkt']):,} pkt"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot backlog from check_backlog_*.txt files."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="check_backlog_*.txt file(s). If omitted, the script asks interactively.",
    )
    parser.add_argument(
        "--active-class",
        default="1:1",
        help="Class whose packet counter defines the active window",
    )
    parser.add_argument(
        "--classes",
        nargs="+",
        default=["1:1", "1:3"],
        help="Classes to plot/summarize",
    )
    parser.add_argument(
        "--x-axis",
        choices=["sample", "time"],
        default="sample",
        help="Use sample index or HH:MM:SS-derived elapsed time for X axis",
    )
    parser.add_argument(
        "--metric",
        choices=["packets", "bytes"],
        default="packets",
        help="Plot backlog packets or backlog bytes",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Moving-average window in samples. Use 0 for raw line graph.",
    )
    parser.add_argument(
        "--include-stop-sample",
        action="store_true",
        help="Include the first sample after the active class stops increasing",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Parent directory for generated output_<input_file> folders",
    )
    return parser.parse_args()


def parse_file_selection(selection: str) -> list[str]:
    if "," in selection:
        tokens = [token.strip() for token in selection.split(",") if token.strip()]
    else:
        tokens = shlex.split(selection)

    return tokens


def prompt_for_files() -> list[str]:
    print("Backlog input file:")
    prompt = "Enter file path, or comma-separated paths: "

    while True:
        selection = input(prompt).strip()
        files = parse_file_selection(selection)
        if files:
            return files

        print("  ! Please enter at least one file.")


def prompt_for_window() -> int:
    prompt = "Moving-average window in samples (0 = raw, 200 = like sojourn plot) [0]: "
    while True:
        value = input(prompt).strip()
        if not value:
            return 0

        try:
            window = int(value)
        except ValueError:
            print("  ! Please enter an integer window size.")
            continue

        if window < 0:
            print("  ! Window must be >= 0.")
            continue

        return window


def main() -> None:
    args = parse_args()
    interactive = not args.files
    if not args.files:
        args.files = prompt_for_files()

    if args.window is None:
        args.window = prompt_for_window() if interactive else 0

    for input_path in args.files:
        analyze_one(args, input_path)


if __name__ == "__main__":
    main()
