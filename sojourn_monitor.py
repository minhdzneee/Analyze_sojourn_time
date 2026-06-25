#!/usr/bin/env python3

import subprocess
import json
import struct
import socket
import time
from collections import defaultdict

IPPROTO_TCP = 6
IPPROTO_UDP = 17

INGRESS_TS_MAP = "/sys/fs/bpf/tc/globals/ingress_ts_map"
EGRESS_TS_MAP = "/sys/fs/bpf/tc/globals/egress_ts_map"
SOJOURN_SAMPLE_MAP = "/sys/fs/bpf/tc/globals/sojourn_sample_map"
INGRESS_COUNT_MAP = "/sys/fs/bpf/tc/globals/ingress_count_map"
EGRESS_COUNT_MAP = "/sys/fs/bpf/tc/globals/egress_count_map"
SOJOURN_DEBUG_MAP = "/sys/fs/bpf/tc/globals/sojourn_debug_map"

DEBUG_LABELS = {
    0: "egress_ipv4",
    1: "egress_udp",
    2: "udp_mark_ok",
    3: "udp_mark_bad",
    4: "record_packet",
    5: "ingress_ts_hit",
    6: "ingress_ts_miss",
    7: "sample_update",
}


def parse_hex_array(hex_list):
    return bytes(int(x, 16) for x in hex_list)


def proto_name(protocol: int) -> str:
    if protocol == IPPROTO_TCP:
        return "TCP"
    if protocol == IPPROTO_UDP:
        return "UDP"
    return str(protocol)


def fetch_ts_map(map_path):
    """Read per-packet timestamp map.

    Key layout must match struct pkt_id:
    src_ip(4), dst_ip(4), src_port(2), dst_port(2), protocol(1), pad(3), seq(4)
    Value layout: u64 timestamp in ns
    """
    try:
        res = subprocess.run(
            ["bpftool", "map", "dump", "pinned", map_path, "-j"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            return {}

        parsed_map = {}
        for entry in json.loads(res.stdout):
            key_bytes = parse_hex_array(entry["key"])
            val_bytes = parse_hex_array(entry["value"])

            if len(key_bytes) < 20 or len(val_bytes) < 8:
                continue

            src_ip = socket.inet_ntoa(key_bytes[0:4])
            dst_ip = socket.inet_ntoa(key_bytes[4:8])
            src_port, dst_port = struct.unpack("<HH", key_bytes[8:12])
            protocol = key_bytes[12]
            pkt_id, = struct.unpack("<I", key_bytes[16:20])
            ts_val, = struct.unpack("<Q", val_bytes[:8])

            pkt_key = (src_ip, dst_ip, src_port, dst_port, protocol, pkt_id)
            parsed_map[pkt_key] = ts_val

        return parsed_map

    except Exception as e:
        print(f"[WARN] fetch_ts_map({map_path}) failed: {e}")
        return {}


def fetch_sojourn_sample_map(map_path=SOJOURN_SAMPLE_MAP):
    """Read egress-computed per-packet sojourn samples.

    Key layout is struct pkt_id.
    Value layout is struct sojourn_sample:
    ingress_ts_ns(8), egress_ts_ns(8), sojourn_ns(8).
    """
    try:
        res = subprocess.run(
            ["bpftool", "map", "dump", "pinned", map_path, "-j"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            return {}

        parsed_map = {}
        for entry in json.loads(res.stdout):
            key_bytes = parse_hex_array(entry["key"])
            val_bytes = parse_hex_array(entry["value"])

            if len(key_bytes) < 20 or len(val_bytes) < 24:
                continue

            src_ip = socket.inet_ntoa(key_bytes[0:4])
            dst_ip = socket.inet_ntoa(key_bytes[4:8])
            src_port, dst_port = struct.unpack("<HH", key_bytes[8:12])
            protocol = key_bytes[12]
            pkt_id, = struct.unpack("<I", key_bytes[16:20])
            ingress_ts, egress_ts, sojourn_ns = struct.unpack("<QQQ", val_bytes[:24])

            pkt_key = (src_ip, dst_ip, src_port, dst_port, protocol, pkt_id)
            parsed_map[pkt_key] = (ingress_ts, egress_ts, sojourn_ns)

        return parsed_map

    except Exception as e:
        print(f"[WARN] fetch_sojourn_sample_map({map_path}) failed: {e}")
        return {}


def fetch_count_map(map_path):
    """Read per-flow counter map.

    Key layout must match struct flow_count_key:
    src_ip(4), dst_ip(4), src_port(2), dst_port(2), protocol(1), pad(3)
    Value layout: u64 packet count
    """
    try:
        res = subprocess.run(
            ["bpftool", "map", "dump", "pinned", map_path, "-j"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            return {}

        parsed_map = {}
        for entry in json.loads(res.stdout):
            key_bytes = parse_hex_array(entry["key"])
            val_bytes = parse_hex_array(entry["value"])

            if len(key_bytes) < 16 or len(val_bytes) < 8:
                continue

            src_ip = socket.inet_ntoa(key_bytes[0:4])
            dst_ip = socket.inet_ntoa(key_bytes[4:8])
            src_port, dst_port = struct.unpack("<HH", key_bytes[8:12])
            protocol = key_bytes[12]
            count, = struct.unpack("<Q", val_bytes[:8])

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            parsed_map[flow_key] = count

        return parsed_map

    except Exception as e:
        print(f"[WARN] fetch_count_map({map_path}) failed: {e}")
        return {}


def fetch_debug_map(map_path=SOJOURN_DEBUG_MAP):
    """Read lightweight egress debug counters."""
    try:
        res = subprocess.run(
            ["bpftool", "map", "dump", "pinned", map_path, "-j"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            return {}

        counters = {}
        for entry in json.loads(res.stdout):
            key_bytes = parse_hex_array(entry["key"])
            val_bytes = parse_hex_array(entry["value"])

            if len(key_bytes) < 4 or len(val_bytes) < 8:
                continue

            key, = struct.unpack("<I", key_bytes[:4])
            value, = struct.unpack("<Q", val_bytes[:8])
            counters[key] = value

        return counters

    except Exception:
        return {}


def format_packet_flow(src_ip, dst_ip, src_port, dst_port, protocol, pkt_id):
    return (
        f"{proto_name(protocol)} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        f" | Seq: {pkt_id}"
    )


def format_count_flow(src_ip, dst_ip, src_port, dst_port, protocol):
    return f"{proto_name(protocol)} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"


def counter_delta(current_counts, baseline_counts, flow_key):
    """Return packets counted since monitor startup for one flow."""
    current = int(current_counts.get(flow_key, 0))
    baseline = int(baseline_counts.get(flow_key, 0))

    # If maps were recreated while the monitor is running, counters can restart
    # from zero. In that case, use the current value as the new-run delta.
    if current < baseline:
        return current
    return current - baseline


def flow_counter_deltas(ingress_counts, egress_counts, ingress_base, egress_base, flow_key):
    in_delta = counter_delta(ingress_counts, ingress_base, flow_key)
    eg_delta = counter_delta(egress_counts, egress_base, flow_key)
    return in_delta, eg_delta, in_delta - eg_delta


def print_counter_summary(ingress_counts, egress_counts, ingress_base, egress_base, flow_stats):
    flow_keys = set(flow_stats.keys()) | set(ingress_counts.keys()) | set(egress_counts.keys())
    rows = []

    for flow_key in flow_keys:
        in_delta, eg_delta, drop_delta = flow_counter_deltas(
            ingress_counts,
            egress_counts,
            ingress_base,
            egress_base,
            flow_key,
        )
        if in_delta == 0 and eg_delta == 0 and flow_key not in flow_stats:
            continue

        drop_rate = (drop_delta / in_delta * 100.0) if in_delta > 0 else 0.0
        rows.append((flow_key, in_delta, eg_delta, drop_delta, drop_rate))

    if not rows:
        print("\n[SUMMARY] No flow counter deltas observed.")
        return

    print("\n[SUMMARY] Counter deltas since monitor start:")
    for flow_key, in_delta, eg_delta, drop_delta, drop_rate in sorted(rows):
        print(
            f"[SUMMARY] {format_count_flow(*flow_key)} | "
            f"InDelta: {in_delta} | EgDelta: {eg_delta} | "
            f"DropDelta: {drop_delta} | DropRate: {drop_rate:.2f}%"
        )


def format_debug_counters(counters):
    if not counters:
        return ""

    parts = []
    for key in sorted(DEBUG_LABELS):
        parts.append(f"{DEBUG_LABELS[key]}={int(counters.get(key, 0))}")
    return " | ".join(parts)


flow_stats = defaultdict(lambda: {"count": 0, "total_ns": 0, "max_ns": 0})
seen_keys = set()
last_debug_print = 0.0

print("Polling eBPF maps for Sojourn Time + In/Eg/Drop (Ctrl+C to stop)...", flush=True)
print("Egress eBPF computes sojourn; Python only prints matched samples.", flush=True)
print("Counter baseline is captured now; start the traffic test after this line.", flush=True)

# Mark old completed packets as already seen, so a new run does not print stale entries.
sample_data_init = fetch_sojourn_sample_map()
seen_keys.update(sample_data_init.keys())

ingress_count_base = fetch_count_map(INGRESS_COUNT_MAP)
egress_count_base = fetch_count_map(EGRESS_COUNT_MAP)

try:
    while True:
        sojourn_samples = fetch_sojourn_sample_map()
        ingress_counts = fetch_count_map(INGRESS_COUNT_MAP)
        egress_counts = fetch_count_map(EGRESS_COUNT_MAP)
        debug_counts = fetch_debug_map()

        items = [
            (pkt_key, sample)
            for pkt_key, sample in sojourn_samples.items()
            if pkt_key not in seen_keys
        ]
        items.sort(key=lambda item: item[1][0])

        for pkt_key, sample in items:
            in_ts, out_ts, sojourn_ns = sample
            if sojourn_ns == 0 or out_ts <= in_ts:
                continue

            src_ip, dst_ip, src_port, dst_port, protocol, pkt_id = pkt_key
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

            # Sojourn stats are counted only for packets observed at both ingress and egress.
            s = flow_stats[flow_key]
            s["count"] += 1
            s["total_ns"] += sojourn_ns
            s["max_ns"] = max(s["max_ns"], sojourn_ns)

            mean_us = (s["total_ns"] / s["count"]) / 1000.0
            max_us = s["max_ns"] / 1000.0

            in_count, eg_count, drop_count = flow_counter_deltas(
                ingress_counts,
                egress_counts,
                ingress_count_base,
                egress_count_base,
                flow_key,
            )

            print(
                f" {format_packet_flow(*pkt_key)} "
                f"InTS: {in_ts} ns | EgTS: {out_ts} ns | "
                f"Sojourn: {sojourn_ns / 1000:.2f} µs | "
                f"Mean: {mean_us:.2f} µs | Max: {max_us:.2f} µs | "
                f"In: {in_count} | Eg: {eg_count} | Drop: {drop_count}",
                flush=True,
            )

            seen_keys.add(pkt_key)

        if not items:
            now = time.time()
            if now - last_debug_print >= 2.0:
                debug_text = format_debug_counters(debug_counts)
                if debug_text:
                    print(f"[DEBUG] No new sojourn samples yet | {debug_text}", flush=True)
                last_debug_print = now

        if len(seen_keys) > 10000:
            seen_keys &= set(sojourn_samples.keys())

        time.sleep(0.05)

except KeyboardInterrupt:
    final_ingress_counts = fetch_count_map(INGRESS_COUNT_MAP)
    final_egress_counts = fetch_count_map(EGRESS_COUNT_MAP)
    print_counter_summary(
        final_ingress_counts,
        final_egress_counts,
        ingress_count_base,
        egress_count_base,
        flow_stats,
    )
