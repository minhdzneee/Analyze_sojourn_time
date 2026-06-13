#!/usr/bin/env python3
"""
Phân tích Sojourn Time từ log eBPF
- Định dạng lại dữ liệu và xuất CSV mới
- Vẽ đồ thị Moving Average với thống kê và thông tin ưu tiên
- Mỗi lần xuất tạo thư mục mới theo thời gian hiện tại
"""

import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import sys
import os
import shutil
from datetime import datetime


PATTERN = re.compile(
    r"^\s*(UDP|TCP)\s+"
    r"([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)\s+\|"
    r"\s+(?:IP_ID|Seq):\s*(\d+)\s+"
    r"Sojourn:\s*([\d.]+)\s*µs\s+\|"
    r"\s*Mean:\s*([\d.]+)\s*µs\s+\|"
    r"\s*Max:\s*([\d.]+)\s*µs"
)


def parse_file(filepath: str) -> pd.DataFrame:
    records = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PATTERN.match(line)
            if m:
                proto, src_ip, src_port, dst_ip, dst_port, id_val, sojourn, mean, max_ = m.groups()
                records.append({
                    "Protocol":     proto,
                    "SRC IP":       src_ip,
                    "SRC Port":     int(src_port),
                    "DST IP":       dst_ip,
                    "DST Port":     int(dst_port),
                    "IP ID / Seq":  int(id_val),
                    "Sojourn (µs)": float(sojourn),
                    "Mean (µs)":    float(mean),
                    "Max (µs)":     float(max_),
                })
    return pd.DataFrame(records)


def export_formatted(df: pd.DataFrame, out_path: str):
    df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"  ✔  Đã xuất: {out_path}  ({len(df):,} dòng)")


def make_output_dir() -> str:
    """Tạo thư mục mới theo thời gian hiện tại: output_YYYYMMDD_HHMMSS"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_name = f"output_{timestamp}"
    os.makedirs(dir_name, exist_ok=True)
    print(f"  ✔  Thư mục xuất: {dir_name}/")
    return dir_name


def compute_stats(df: pd.DataFrame, ip: str,
                  pkt_start: int = 0, pkt_end: int = None) -> dict:
    """Tính thống kê cho một luồng IP."""
    sub = df[df["DST IP"] == ip]["Sojourn (µs)"]
    if pkt_end is not None:
        sub = sub.iloc[pkt_start:pkt_end]
    if sub.empty:
        return None
    return {
        "n":      len(sub),
        "mean":   sub.mean(),
        "median": sub.median(),
        "max":    sub.max(),
        "std":    sub.std(),
    }


def add_stats_box(ax, stats: dict, ip: str, color: str,
                  x_pos: float, y_pos: float):
    """Thêm hộp thống kê vào đồ thị."""
    if stats is None:
        return
    short = ip.split(".")[-1]
    text = (
        f".{short}  (n={stats['n']:,})\n"
        f"Mean {stats['mean']:.2f}  Med {stats['median']:.2f}\n"
        f"Max  {stats['max']:.2f}  Std {stats['std']:.2f}"
    )
    ax.text(
        x_pos, y_pos, text,
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


def plot_comparison(df_cls: pd.DataFrame,
                    df_no_cls: pd.DataFrame,
                    ip1: str, ip2: str,
                    priority_ip: str,
                    priority_label: str,
                    window: int = 200,
                    pkt_start: int = 0,
                    pkt_end: int = None,
                    out_path: str = "sojourn_comparison.png"):

    colors  = {ip1: "#1E88E5", ip2: "#FB8C00"}
    suffix1 = ip1.split(".")[-1]
    suffix2 = ip2.split(".")[-1]

    zoom_tag = f"  [Gói {pkt_start}–{pkt_end}]" if pkt_end is not None else ""

    # Priority label hiển thị trên đồ thị
    priority_short = priority_ip.split(".")[-1]
    priority_info  = f"Ưu tiên: .{priority_short} ({priority_label})"

    fig, axes = plt.subplots(2, 1, figsize=(15, 11))
    fig.patch.set_facecolor("white")
    fig.suptitle(
        f"Sojourn Time Trend — .{suffix1} vs .{suffix2}   |   {priority_info}",
        fontsize=13, fontweight="bold", y=0.99
    )

    configs = [
        (df_cls,
         f"CLS Scenario (Window={window}){zoom_tag}",
         axes[0]),
        (df_no_cls,
         f"No-CLS Scenario (Window={window}){zoom_tag}",
         axes[1]),
    ]

    for df, title, ax in configs:
        ax.set_facecolor("white")

        # Vẽ đường priority trước (nằm dưới) để đường còn lại đè lên
        plot_order = [priority_ip, ip1 if priority_ip == ip2 else ip2]

        for ip in plot_order:
            subset = df[df["DST IP"] == ip].reset_index(drop=True)
            if subset.empty:
                continue
            if pkt_end is not None:
                subset = subset.iloc[pkt_start:pkt_end].reset_index(drop=True)
            if subset.empty:
                continue

            actual_window = min(window, max(1, len(subset) // 5))
            ma = subset["Sojourn (µs)"].rolling(window=actual_window, min_periods=1).mean()
            short = ip.split(".")[-1]

            is_priority = (ip == priority_ip)
            lw    = 2.2 if is_priority else 1.3
            alpha = 1.0 if is_priority else 0.75
            label = f"→ .{short} (Moving Avg)" + (" ★ Priority" if is_priority else "")

            ax.plot(
                subset.index + pkt_start,
                ma,
                label=label,
                color=colors[ip],
                linewidth=lw,
                alpha=alpha,
            )

        ax.set_title(title, fontsize=11, pad=6)
        ax.set_ylabel("Sojourn Time (µs)", fontsize=10)
        ax.legend(fontsize=9, loc="upper left")
        ax.grid(True, linestyle="--", alpha=0.4, color="gray")
        ax.tick_params(labelsize=9)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        # Chú thích ưu tiên — đặt dưới title, căn trái cùng legend
        ax.annotate(
            f"★ Luồng được ưu tiên: .{priority_short} — {priority_label}",
            xy=(0.0, 1.01), xycoords="axes fraction",
            ha="left", va="bottom", fontsize=8.5,
            color=colors[priority_ip],
            fontweight="bold",
        )

        # Hộp thống kê nhỏ gọn — góc trên phải, xếp dọc sát nhau
        s1 = compute_stats(df, ip1, pkt_start, pkt_end)
        s2 = compute_stats(df, ip2, pkt_start, pkt_end)
        add_stats_box(ax, s1, ip1, colors[ip1], x_pos=0.822, y_pos=0.99)
        add_stats_box(ax, s2, ip2, colors[ip2], x_pos=0.822, y_pos=0.72)

    axes[1].set_xlabel("Packet Index", fontsize=10)
    plt.tight_layout(pad=2.5)
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    print(f"  ✔  Đã lưu đồ thị: {out_path}")
    plt.show()


def get_input(prompt: str, default: str) -> str:
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default


def main():
    print("=" * 60)
    print("  PHÂN TÍCH SOJOURN TIME - eBPF Log")
    print("=" * 60)

    # ── File đầu vào ──
    file_cls    = get_input("File CLS    ", "2026_06_09_cls_3.csv")
    file_no_cls = get_input("File No-CLS ", "2026_06_09_no_cls_3.csv")
    for f in (file_cls, file_no_cls):
        if not os.path.isfile(f):
            print(f"  ✘  Không tìm thấy file: {f}")
            sys.exit(1)

    # ── IP đích ──
    print()
    ip1 = get_input("IP đích 1", "192.168.3.213")
    ip2 = get_input("IP đích 2", "192.168.3.123")

    # ── Thông tin ưu tiên ──
    print()
    print("Thông tin gói tin được ưu tiên:")
    priority_choice = get_input(f"  IP được ưu tiên ({ip1} hoặc {ip2})", ip1)
    priority_ip = priority_choice if priority_choice in (ip1, ip2) else ip1
    priority_label = get_input("  Mô tả ưu tiên (vd: DSCP EF, Queue 0, CLS High)", "High Priority")

    # ── Moving Average ──
    win_str = get_input("\nCửa sổ Moving Average (số gói)", "200")
    try:
        window = max(1, int(win_str))
    except ValueError:
        window = 200

    # ── Zoom ──
    print()
    print("Zoom vào khoảng gói tin? (Enter để vẽ toàn bộ)")
    start_str = get_input("  Gói bắt đầu", "0")
    end_str   = get_input("  Gói kết thúc (Enter = hết)", "")
    try:
        pkt_start = int(start_str)
    except ValueError:
        pkt_start = 0
    pkt_end = None
    if end_str.strip():
        try:
            pkt_end = int(end_str)
        except ValueError:
            pkt_end = None

    # ── Parsing ──
    print("\nĐang đọc dữ liệu...")
    df_cls    = parse_file(file_cls)
    df_no_cls = parse_file(file_no_cls)
    print(f"  • CLS   : {len(df_cls):,} bản ghi")
    print(f"  • No-CLS: {len(df_no_cls):,} bản ghi")
    if df_cls.empty or df_no_cls.empty:
        print("  ✘  Không parse được dữ liệu.")
        sys.exit(1)

    # ── Tạo thư mục output theo thời gian ──
    print()
    out_dir = make_output_dir()

    # ── Sao chép file gốc ──
    print("Sao chép file gốc...")
    for src in (file_cls, file_no_cls):
        dst = os.path.join(out_dir, os.path.basename(src))
        shutil.copy2(src, dst)
        print(f"  ✔  Đã sao chép: {dst}")

    # ── Xuất CSV đã định dạng ──
    print("Xuất CSV đã định dạng...")
    base_cls    = os.path.splitext(os.path.basename(file_cls))[0]
    base_no_cls = os.path.splitext(os.path.basename(file_no_cls))[0]
    export_formatted(df_cls,    os.path.join(out_dir, f"{base_cls}_formatted.csv"))
    export_formatted(df_no_cls, os.path.join(out_dir, f"{base_no_cls}_formatted.csv"))

    # ── Vẽ đồ thị ──
    zoom_suffix = f"_zoom_{pkt_start}_{pkt_end}" if pkt_end else ""
    chart_name  = f"sojourn_comparison{zoom_suffix}.png"
    out_path    = os.path.join(out_dir, chart_name)

    print("Vẽ đồ thị...")
    plot_comparison(
        df_cls, df_no_cls, ip1, ip2,
        priority_ip=priority_ip,
        priority_label=priority_label,
        window=window,
        pkt_start=pkt_start,
        pkt_end=pkt_end,
        out_path=out_path,
    )

    # ── Thống kê terminal ──
    print("\n" + "=" * 60)
    print("  THỐNG KÊ TÓM TẮT")
    print("=" * 60)
    for label, df in [("CLS", df_cls), ("No-CLS", df_no_cls)]:
        print(f"\n[{label}]")
        for ip in (ip1, ip2):
            s = compute_stats(df, ip, pkt_start, pkt_end)
            tag = " ★" if ip == priority_ip else ""
            if s is None:
                print(f"  DST {ip}: không có dữ liệu")
            else:
                print(f"  DST {ip}{tag}: n={s['n']:,}  |  "
                      f"Mean={s['mean']:.2f} µs  |  "
                      f"Median={s['median']:.2f} µs  |  "
                      f"Max={s['max']:.2f} µs  |  "
                      f"Std={s['std']:.2f} µs")

    print(f"\n✔  Tất cả file đã lưu vào: {out_dir}/")


if __name__ == "__main__":
    main()