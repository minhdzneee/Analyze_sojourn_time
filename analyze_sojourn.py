#!/usr/bin/env python3
"""
Analyze Sojourn Time from eBPF logs.

UDP-only version:
- Parse Sojourn, Mean, Max, In, Eg, Drop from sojourn_monitor.py output.
- Compare one or more scenario files, e.g. CLS and/or No-CLS.
- File inputs are optional: press Enter to skip a file.
- If a file does not exist, it is skipped instead of stopping the program.
- Plot only UDP packets by default, so TCP iperf3 control packets do not distort the graph.
- Optional filter by UDP destination port, default 5201.
"""

import os
import re
import shutil
import sys
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd

PATTERN = re.compile(
    r"^\s*(UDP|TCP)\s+"
    r"([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)\s+\|"
    r"\s+(?:IP_ID|Seq):\s*(\d+)\s+"
    r"(?:InTS:\s*(\d+)\s*ns\s+\|\s*EgTS:\s*(\d+)\s*ns\s+\|\s*)?"
    r"Sojourn:\s*([\d.]+)\s*µs\s+\|"
    r"\s*Mean:\s*([\d.]+)\s*µs\s+\|"
    r"\s*Max:\s*([\d.]+)\s*µs"
    r"(?:\s+\|\s*In:\s*(\d+)\s+\|\s*Eg:\s*(\d+)\s+\|\s*Drop:\s*(-?\d+))?"
)


def parse_file(filepath: str) -> pd.DataFrame:
    records = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PATTERN.match(line)
            if not m:
                continue

            (
                proto,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                id_val,
                in_ts,
                eg_ts,
                sojourn,
                mean,
                max_,
                in_count,
                eg_count,
                drop_count,
            ) = m.groups()

            records.append(
                {
                    "Protocol": proto.upper(),
                    "SRC IP": src_ip,
                    "SRC Port": int(src_port),
                    "DST IP": dst_ip,
                    "DST Port": int(dst_port),
                    "IP ID / Seq": int(id_val),
                    "InTS (ns)": int(in_ts) if in_ts is not None else 0,
                    "EgTS (ns)": int(eg_ts) if eg_ts is not None else 0,
                    "Sojourn (µs)": float(sojourn),
                    "Mean (µs)": float(mean),
                    "Max (µs)": float(max_),
                    "In": int(in_count) if in_count is not None else 0,
                    "Eg": int(eg_count) if eg_count is not None else 0,
                    "Drop": int(drop_count) if drop_count is not None else 0,
                }
            )

    return pd.DataFrame(records)


def filter_udp(df: pd.DataFrame, dst_port: int | None = 5201) -> pd.DataFrame:
    """Keep UDP packets only. Optionally keep only one UDP destination port."""
    if df.empty:
        return df

    filtered = df[df["Protocol"].astype(str).str.upper() == "UDP"].copy()

    if dst_port is not None:
        filtered = filtered[filtered["DST Port"].astype(int) == int(dst_port)].copy()

    return filtered.reset_index(drop=True)


def get_input(prompt: str, default: str) -> str:
    """Normal input: pressing Enter uses the default value."""
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default


def get_optional_file(prompt: str, example: str = "") -> str | None:
    """File input: pressing Enter means skip, not use default."""
    suffix = f" [example: {example}]" if example else ""
    val = input(f"{prompt}{suffix} (Enter = skip): ").strip()
    if not val:
        print(f" ↷ Skipped: {prompt}")
        return None
    if not os.path.isfile(val):
        print(f" ⚠ File not found, skipped: {val}")
        return None
    return val


def make_output_dir() -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_name = f"output_{timestamp}"
    os.makedirs(dir_name, exist_ok=True)
    print(f" ✔ Output directory: {dir_name}/")
    return dir_name


def export_formatted(df: pd.DataFrame, out_path: str):
    df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f" ✔ Exported: {out_path} ({len(df):,} rows)")


def filter_flow(df: pd.DataFrame, src_ip: str, dst_ip: str) -> pd.DataFrame:
    return df[(df["SRC IP"] == src_ip) & (df["DST IP"] == dst_ip)].reset_index(drop=True)


def get_time_origin_ns(df: pd.DataFrame) -> int | None:
    """Return the first ingress timestamp in a parsed log, if available."""
    if "InTS (ns)" not in df.columns or df.empty:
        return None

    ts = pd.to_numeric(df["InTS (ns)"], errors="coerce")
    ts = ts[ts > 0]
    if ts.empty:
        return None
    return int(ts.min())


def compute_stats(
    df: pd.DataFrame,
    src_ip: str,
    dst_ip: str,
    pkt_start: int = 0,
    pkt_end: int | None = None,
) -> dict | None:
    sub = filter_flow(df, src_ip, dst_ip)

    if pkt_end is not None:
        sub = sub.iloc[pkt_start:pkt_end]
    else:
        sub = sub.iloc[pkt_start:]

    if sub.empty:
        return None

    soj = sub["Sojourn (µs)"]

    # In/Eg/Drop are cumulative counters printed per exact 5-tuple.
    # For an IP-pair flow, sum the last/max counter of each 5-tuple inside it.
    if {"Protocol", "SRC Port", "DST Port", "In", "Eg", "Drop"}.issubset(sub.columns):
        flow_totals = (
            sub.groupby(["Protocol", "SRC IP", "SRC Port", "DST IP", "DST Port"], as_index=False)
            .agg({"In": "max", "Eg": "max", "Drop": "max"})
        )
        in_total = int(flow_totals["In"].sum())
        eg_total = int(flow_totals["Eg"].sum())
        drop_total = int(flow_totals["Drop"].sum())
    else:
        in_total = eg_total = drop_total = 0

    return {
        "n": len(sub),
        "mean": soj.mean(),
        "median": soj.median(),
        "max": soj.max(),
        "std": soj.std(),
        "in": in_total,
        "eg": eg_total,
        "drop": drop_total,
    }


def flow_label(src_ip: str, dst_ip: str) -> str:
    return f".{src_ip.split('.')[-1]}→.{dst_ip.split('.')[-1]}"


def add_stats_box(ax, stats: dict | None, src_ip: str, dst_ip: str, color: str, x_pos: float, y_pos: float):
    if stats is None:
        return

    text = (
        f"{flow_label(src_ip, dst_ip)} (n={stats['n']:,})\n"
        f"Mean {stats['mean']:.2f} Med {stats['median']:.2f}\n"
        f"Max {stats['max']:.2f} Std {stats['std']:.2f}\n"
        f"In {stats['in']:,} Eg {stats['eg']:,} Drop {stats['drop']:,}"
    )

    ax.text(
        x_pos,
        y_pos,
        text,
        transform=ax.transAxes,
        fontsize=7.5,
        verticalalignment="top",
        fontfamily="monospace",
        linespacing=1.4,
        bbox=dict(
            boxstyle="round,pad=0.3",
            facecolor="white",
            edgecolor=color,
            linewidth=1.2,
            alpha=0.90,
        ),
        color=color,
    )


def plot_scenarios(
    scenarios: list[tuple[str, str, pd.DataFrame]],
    flow1: tuple[str, str],
    flow2: tuple[str, str],
    priority_flow: tuple[str, str],
    priority_label: str,
    window: int = 200,
    pkt_start: int = 0,
    pkt_end: int | None = None,
    out_path: str = "sojourn_comparison.png",
    udp_port: int | None = 5201,
    x_axis: str = "index",
):
    if x_axis not in {"index", "time"}:
        raise ValueError("x_axis must be 'index' or 'time'")

    colors = {flow1: "#1E88E5", flow2: "#FB8C00"}
    zoom_tag = f" [Packets {pkt_start}–{pkt_end}]" if pkt_end is not None else ""
    priority_info = f"Priority: {flow_label(*priority_flow)} ({priority_label})"
    port_info = f"UDP dst port {udp_port}" if udp_port is not None else "UDP only"
    axis_info = "Ingress time" if x_axis == "time" else "Packet index"

    n = len(scenarios)
    fig_height = 6 if n == 1 else 5.5 * n
    fig, axes = plt.subplots(n, 1, figsize=(16, fig_height))
    if n == 1:
        axes = [axes]

    fig.patch.set_facecolor("white")
    fig.suptitle(
        f"Sojourn Time Trend | {flow_label(*flow1)} vs {flow_label(*flow2)} | {priority_info} | {port_info} | X: {axis_info}",
        fontsize=13,
        fontweight="bold",
        y=0.99,
    )

    plot_order = [priority_flow, flow1 if priority_flow == flow2 else flow2]

    for ax, (label_name, file_path, df) in zip(axes, scenarios):
        ax.set_facecolor("white")
        time_origin_ns = get_time_origin_ns(df)

        plotted_any = False
        for src_ip, dst_ip in plot_order:
            subset = filter_flow(df, src_ip, dst_ip)
            if x_axis == "time":
                if time_origin_ns is None or "InTS (ns)" not in subset.columns:
                    continue
                subset = subset.copy()
                subset["InTS (ns)"] = pd.to_numeric(subset["InTS (ns)"], errors="coerce")
                subset = subset[subset["InTS (ns)"] > 0].sort_values("InTS (ns)").reset_index(drop=True)

            if pkt_end is not None:
                subset = subset.iloc[pkt_start:pkt_end].reset_index(drop=True)
            else:
                subset = subset.iloc[pkt_start:].reset_index(drop=True)

            if subset.empty:
                continue

            actual_window = min(window, max(1, len(subset) // 5))
            ma = subset["Sojourn (µs)"].rolling(window=actual_window, min_periods=1).mean()
            if x_axis == "time":
                x_values = (subset["InTS (ns)"] - time_origin_ns) / 1_000_000_000.0
            else:
                x_values = subset.index + pkt_start

            is_priority = (src_ip, dst_ip) == priority_flow
            line_label = f"{flow_label(src_ip, dst_ip)} UDP Moving Avg" + (" ★ Priority" if is_priority else "")
            ax.plot(
                x_values,
                ma,
                label=line_label,
                color=colors[(src_ip, dst_ip)],
                linewidth=2.2 if is_priority else 1.3,
                alpha=1.0 if is_priority else 0.75,
            )
            plotted_any = True

        ax.set_title(
            f"{label_name} Scenario — {os.path.basename(file_path)} (Window={window} packets, X={axis_info}){zoom_tag}",
            fontsize=11,
            pad=6,
        )
        ax.set_ylabel("Sojourn Time (µs)", fontsize=10)
        ax.grid(True, linestyle="--", alpha=0.4, color="gray")
        ax.tick_params(labelsize=9)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        if plotted_any:
            ax.legend(fontsize=9, loc="upper left")
        else:
            ax.text(
                0.5,
                0.5,
                "No timestamp data for selected flows" if x_axis == "time" else "No UDP data for selected flows",
                transform=ax.transAxes,
                ha="center",
                va="center",
                fontsize=11,
            )

        ax.annotate(
            f"★ Priority Flow: {flow_label(*priority_flow)} — {priority_label}",
            xy=(0.0, 1.01),
            xycoords="axes fraction",
            ha="left",
            va="bottom",
            fontsize=8.5,
            color=colors[priority_flow],
            fontweight="bold",
        )

        s1 = compute_stats(df, *flow1, pkt_start, pkt_end)
        s2 = compute_stats(df, *flow2, pkt_start, pkt_end)
        add_stats_box(ax, s1, *flow1, colors[flow1], x_pos=0.78, y_pos=0.99)
        add_stats_box(ax, s2, *flow2, colors[flow2], x_pos=0.78, y_pos=0.67)

    axes[-1].set_xlabel("Ingress Time Since First Parsed Packet (s)" if x_axis == "time" else "Packet Index", fontsize=10)
    plt.tight_layout(pad=2.5)
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    print(f" ✔ Plot saved: {out_path}")
    plt.close(fig)


def main():
    print("=" * 70)
    print(" SOJOURN TIME ANALYSIS - UDP only")
    print("=" * 70)

    file_inputs = [
        ("CLS", get_optional_file("CLS file", "2026_06_09_cls_3.csv")),
        ("No-CLS", get_optional_file("No-CLS file", "2026_06_09_no_cls_3.csv")),
    ]
    file_inputs = [(label, path) for label, path in file_inputs if path is not None]

    if not file_inputs:
        print(" ✘ No valid input files. Nothing to analyze.")
        sys.exit(1)

    print("\nUDP filter:")
    port_str = input("UDP destination port (Enter = 5201, type all = all UDP ports): ").strip()
    if not port_str:
        udp_port = 5201
    elif port_str.lower() in {"all", "*", "any"}:
        udp_port = None
    else:
        try:
            udp_port = int(port_str)
        except ValueError:
            print(" ⚠ Invalid port. Using default UDP dst port 5201.")
            udp_port = 5201

    print("\nFlow information:")
    flow1_src = get_input("Flow 1 SRC IP", "192.168.3.103")
    flow1_dst = get_input("Flow 1 DST IP", "192.168.3.122")
    flow2_src = get_input("Flow 2 SRC IP", "192.168.3.103")
    flow2_dst = get_input("Flow 2 DST IP", "192.168.3.111")

    flow1 = (flow1_src, flow1_dst)
    flow2 = (flow2_src, flow2_dst)

    print("\nPriority flow information:")
    priority_choice = get_input("Priority flow (1 or 2)", "1")
    priority_flow = flow1 if priority_choice != "2" else flow2
    priority_label = get_input("Priority description", "High Priority")

    win_str = get_input("\nMoving Average Window (packets)", "200")
    try:
        window = max(1, int(win_str))
    except ValueError:
        window = 200

    print("\nZoom into packet range? (Press Enter for full dataset)")
    start_str = get_input("Start packet", "0")
    end_str = input("End packet (Enter = end): ").strip()

    try:
        pkt_start = int(start_str)
    except ValueError:
        pkt_start = 0

    pkt_end = None
    if end_str:
        try:
            pkt_end = int(end_str)
        except ValueError:
            pkt_end = None

    print("\nReading data...")
    scenarios = []
    for label, path in file_inputs:
        df_raw = parse_file(path)
        df = filter_udp(df_raw, udp_port)
        print(f" • {label:<6}: parsed {len(df_raw):,} records, kept {len(df):,} UDP records from {path}")
        if df.empty:
            print(f" ⚠ No UDP data after filtering, skipped: {path}")
            continue
        scenarios.append((label, path, df))

    if not scenarios:
        print(" ✘ Failed to parse any valid UDP data.")
        sys.exit(1)

    out_dir = make_output_dir()

    print("Copying original files...")
    for _, src, _ in scenarios:
        dst = os.path.join(out_dir, os.path.basename(src))
        shutil.copy2(src, dst)
        print(f" ✔ Copied: {dst}")

    print("Exporting UDP-only formatted CSV files...")
    for label, src, df in scenarios:
        base = os.path.splitext(os.path.basename(src))[0]
        suffix = "udp" if udp_port is None else f"udp_dst{udp_port}"
        export_formatted(df, os.path.join(out_dir, f"{base}_{suffix}_formatted.csv"))

    zoom_suffix = f"_zoom_{pkt_start}_{pkt_end}" if pkt_end else ""
    port_suffix = "udp_all" if udp_port is None else f"udp_dst{udp_port}"
    index_out_path = os.path.join(out_dir, f"sojourn_comparison_{port_suffix}_index{zoom_suffix}.png")
    time_out_path = os.path.join(out_dir, f"sojourn_comparison_{port_suffix}_time{zoom_suffix}.png")

    print("Generating packet-index plot...")
    plot_scenarios(
        scenarios,
        flow1,
        flow2,
        priority_flow=priority_flow,
        priority_label=priority_label,
        window=window,
        pkt_start=pkt_start,
        pkt_end=pkt_end,
        out_path=index_out_path,
        udp_port=udp_port,
        x_axis="index",
    )

    if any(get_time_origin_ns(df) is not None for _, _, df in scenarios):
        print("Generating timestamp plot...")
        plot_scenarios(
            scenarios,
            flow1,
            flow2,
            priority_flow=priority_flow,
            priority_label=priority_label,
            window=window,
            pkt_start=pkt_start,
            pkt_end=pkt_end,
            out_path=time_out_path,
            udp_port=udp_port,
            x_axis="time",
        )
    else:
        print(" ⚠ No InTS/EgTS fields found. Timestamp plot was not generated for this log.")

    print("\n" + "=" * 70)
    print(" SUMMARY STATISTICS - UDP only")
    print("=" * 70)

    for label, _, df in scenarios:
        print(f"\n[{label}]")
        for i, flow in enumerate((flow1, flow2), start=1):
            s = compute_stats(df, *flow, pkt_start, pkt_end)
            tag = " ★" if flow == priority_flow else ""
            if s is None:
                print(f" Flow {i} {flow[0]} -> {flow[1]}: no UDP data")
            else:
                print(
                    f" Flow {i} {flow[0]} -> {flow[1]}{tag}: "
                    f"n={s['n']:,} | Mean={s['mean']:.2f} µs | "
                    f"Median={s['median']:.2f} µs | Max={s['max']:.2f} µs | "
                    f"Std={s['std']:.2f} µs | In={s['in']:,} | "
                    f"Eg={s['eg']:,} | Drop={s['drop']:,}"
                )

    print(f"\n✔ All files have been saved to: {out_dir}/")


if __name__ == "__main__":
    main()
