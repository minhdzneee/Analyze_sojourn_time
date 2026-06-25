#!/usr/bin/env python3
"""Read eBPF-computed sojourn statistics from sojourn_stats_map.

This is the high-bitrate path. The egress TC program computes sojourn time in
kernel and stores per-flow aggregate stats; this script only reads aggregates.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field


IPPROTO_TCP = 6
IPPROTO_UDP = 17
SOJOURN_HIST_BUCKETS = 32
SOJOURN_STATS_MAP = "/sys/fs/bpf/tc/globals/sojourn_stats_map"


@dataclass
class FlowStats:
    protocol: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    matched: int = 0
    lookup_miss: int = 0
    nonpositive: int = 0
    sum_ns: int = 0
    min_ns: int = 0
    max_ns: int = 0
    buckets: list[int] = field(default_factory=lambda: [0] * SOJOURN_HIST_BUCKETS)

    def merge(self, other: "FlowStats") -> None:
        self.matched += other.matched
        self.lookup_miss += other.lookup_miss
        self.nonpositive += other.nonpositive
        self.sum_ns += other.sum_ns
        if other.min_ns and (self.min_ns == 0 or other.min_ns < self.min_ns):
            self.min_ns = other.min_ns
        if other.max_ns > self.max_ns:
            self.max_ns = other.max_ns
        self.buckets = [a + b for a, b in zip(self.buckets, other.buckets)]

    @property
    def observed(self) -> int:
        return self.matched + self.lookup_miss + self.nonpositive

    @property
    def mean_us(self) -> float:
        return (self.sum_ns / self.matched / 1000.0) if self.matched else 0.0

    @property
    def min_us(self) -> float:
        return self.min_ns / 1000.0 if self.min_ns else 0.0

    @property
    def max_us(self) -> float:
        return self.max_ns / 1000.0 if self.max_ns else 0.0

    @property
    def match_rate(self) -> float:
        return (self.matched / self.observed * 100.0) if self.observed else 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read eBPF egress-computed sojourn stats."
    )
    parser.add_argument(
        "--map",
        default=SOJOURN_STATS_MAP,
        help="Pinned sojourn_stats_map path",
    )
    parser.add_argument(
        "--watch",
        type=float,
        default=0.0,
        help="Repeat every N seconds. Default 0 prints once.",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Write the current snapshot to a CSV file.",
    )
    parser.add_argument(
        "--group-by",
        choices=["ip-pair", "five-tuple"],
        default="ip-pair",
        help="Aggregate by IP pair plus dst port, or keep exact 5-tuples.",
    )
    parser.add_argument(
        "--protocol",
        choices=["udp", "tcp", "all"],
        default="udp",
        help="Protocol filter.",
    )
    parser.add_argument(
        "--dst-port",
        type=int,
        default=5201,
        help="Destination port filter. Use 0 for all ports.",
    )
    parser.add_argument("--src-ip", default=None, help="Optional source IP filter.")
    parser.add_argument("--dst-ip", default=None, help="Optional destination IP filter.")
    return parser.parse_args()


def parse_hex_array(hex_list: list[str]) -> bytes:
    return bytes(int(x, 16) for x in hex_list)


def proto_name(protocol: int) -> str:
    if protocol == IPPROTO_TCP:
        return "TCP"
    if protocol == IPPROTO_UDP:
        return "UDP"
    return str(protocol)


def parse_flow_key(hex_list: list[str]) -> tuple[int, str, int, str, int]:
    key = parse_hex_array(hex_list)
    if len(key) < 16:
        raise ValueError("flow key shorter than 16 bytes")

    src_ip = socket.inet_ntoa(key[0:4])
    dst_ip = socket.inet_ntoa(key[4:8])
    src_port, dst_port = struct.unpack("<HH", key[8:12])
    protocol = key[12]
    return protocol, src_ip, src_port, dst_ip, dst_port


def entry_value_blobs(entry: dict) -> list[list[str]]:
    if "value" in entry:
        return [entry["value"]]

    values = entry.get("values") or entry.get("per_cpu_values")
    if values is None:
        return []

    if isinstance(values, dict):
        values = list(values.values())

    blobs = []
    for item in values:
        if isinstance(item, dict) and "value" in item:
            blobs.append(item["value"])
        elif isinstance(item, list):
            blobs.append(item)
    return blobs


def parse_stats_value(hex_list: list[str], flow_key: tuple[int, str, int, str, int]) -> FlowStats:
    value = parse_hex_array(hex_list)
    min_len = (6 + SOJOURN_HIST_BUCKETS) * 8
    if len(value) < min_len:
        raise ValueError(f"stats value shorter than {min_len} bytes")

    matched, lookup_miss, nonpositive, sum_ns, min_ns, max_ns = struct.unpack_from(
        "<QQQQQQ", value, 0
    )
    buckets = list(
        struct.unpack_from(f"<{SOJOURN_HIST_BUCKETS}Q", value, 6 * 8)
    )
    protocol, src_ip, src_port, dst_ip, dst_port = flow_key
    return FlowStats(
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        matched=matched,
        lookup_miss=lookup_miss,
        nonpositive=nonpositive,
        sum_ns=sum_ns,
        min_ns=min_ns,
        max_ns=max_ns,
        buckets=buckets,
    )


def fetch_stats(map_path: str) -> list[FlowStats]:
    res = subprocess.run(
        ["bpftool", "map", "dump", "pinned", map_path, "-j"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or res.stdout.strip() or "bpftool failed")

    rows: list[FlowStats] = []
    for entry in json.loads(res.stdout):
        flow_key = parse_flow_key(entry["key"])
        merged: FlowStats | None = None

        for blob in entry_value_blobs(entry):
            stats = parse_stats_value(blob, flow_key)
            if merged is None:
                merged = stats
            else:
                merged.merge(stats)

        if merged is not None:
            rows.append(merged)

    return rows


def aggregate_rows(rows: list[FlowStats], group_by: str) -> list[FlowStats]:
    if group_by == "five-tuple":
        return rows

    grouped: dict[tuple[int, str, str, int], FlowStats] = {}
    for row in rows:
        key = (row.protocol, row.src_ip, row.dst_ip, row.dst_port)
        if key not in grouped:
            grouped[key] = FlowStats(
                protocol=row.protocol,
                src_ip=row.src_ip,
                src_port=0,
                dst_ip=row.dst_ip,
                dst_port=row.dst_port,
            )
        grouped[key].merge(row)

    return list(grouped.values())


def filter_rows(rows: list[FlowStats], args: argparse.Namespace) -> list[FlowStats]:
    out = []
    for row in rows:
        if args.protocol == "udp" and row.protocol != IPPROTO_UDP:
            continue
        if args.protocol == "tcp" and row.protocol != IPPROTO_TCP:
            continue
        if args.dst_port and row.dst_port != args.dst_port:
            continue
        if args.src_ip and row.src_ip != args.src_ip:
            continue
        if args.dst_ip and row.dst_ip != args.dst_ip:
            continue
        out.append(row)
    return out


def bucket_upper_us(bucket: int) -> int:
    return 1 << bucket


def percentile_us(stats: FlowStats, q: float) -> float:
    if stats.matched <= 0:
        return 0.0

    target = max(1, int(stats.matched * q + 0.999999))
    running = 0
    for idx, count in enumerate(stats.buckets):
        running += count
        if running >= target:
            return float(bucket_upper_us(idx))
    return float(bucket_upper_us(SOJOURN_HIST_BUCKETS - 1))


def flow_label(row: FlowStats) -> str:
    if row.src_port:
        return f"{proto_name(row.protocol)} {row.src_ip}:{row.src_port} -> {row.dst_ip}:{row.dst_port}"
    return f"{proto_name(row.protocol)} {row.src_ip} -> {row.dst_ip}:{row.dst_port}"


def row_dict(row: FlowStats) -> dict[str, object]:
    return {
        "protocol": proto_name(row.protocol),
        "src_ip": row.src_ip,
        "src_port": row.src_port if row.src_port else "",
        "dst_ip": row.dst_ip,
        "dst_port": row.dst_port,
        "matched": row.matched,
        "lookup_miss": row.lookup_miss,
        "nonpositive": row.nonpositive,
        "observed": row.observed,
        "match_rate_pct": f"{row.match_rate:.2f}",
        "mean_us": f"{row.mean_us:.2f}",
        "min_us": f"{row.min_us:.2f}",
        "p50_us": f"{percentile_us(row, 0.50):.2f}",
        "p95_us": f"{percentile_us(row, 0.95):.2f}",
        "p99_us": f"{percentile_us(row, 0.99):.2f}",
        "max_us": f"{row.max_us:.2f}",
    }


def print_rows(rows: list[FlowStats]) -> None:
    if not rows:
        print("No sojourn stats found for selected filters.")
        return

    rows = sorted(rows, key=lambda r: (r.dst_ip, r.dst_port, r.src_ip, r.src_port))
    print(
        "Flow | Matched | Miss | Match% | Mean_us | Min_us | P50_us | "
        "P95_us | P99_us | Max_us"
    )
    for row in rows:
        print(
            f"{flow_label(row)} | "
            f"{row.matched:,} | "
            f"{row.lookup_miss:,} | "
            f"{row.match_rate:6.2f} | "
            f"{row.mean_us:8.2f} | "
            f"{row.min_us:7.2f} | "
            f"{percentile_us(row, 0.50):7.2f} | "
            f"{percentile_us(row, 0.95):7.2f} | "
            f"{percentile_us(row, 0.99):7.2f} | "
            f"{row.max_us:8.2f}"
        )


def write_csv(path: str, rows: list[FlowStats]) -> None:
    fields = list(row_dict(FlowStats(IPPROTO_UDP, "", 0, "", 0)).keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (r.dst_ip, r.dst_port, r.src_ip, r.src_port)):
            writer.writerow(row_dict(row))


def read_once(args: argparse.Namespace) -> list[FlowStats]:
    rows = fetch_stats(args.map)
    rows = filter_rows(rows, args)
    return aggregate_rows(rows, args.group_by)


def main() -> None:
    args = parse_args()

    while True:
        rows = read_once(args)
        print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] sojourn_stats_map")
        print_rows(rows)

        if args.csv:
            write_csv(args.csv, rows)
            print(f"CSV saved: {args.csv}")

        if args.watch <= 0:
            break

        time.sleep(args.watch)


if __name__ == "__main__":
    main()
