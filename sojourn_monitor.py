#!/usr/bin/env python3
import subprocess
import json
import struct
import socket
import time
from collections import defaultdict

IPPROTO_TCP = 6
IPPROTO_UDP = 17

def parse_hex_array(hex_list):
    return bytes(int(x, 16) for x in hex_list)

def fetch_map(map_path):
    try:
        res = subprocess.run(
            ['bpftool', 'map', 'dump', 'pinned', map_path, '-j'],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            return {}

        parsed_map = {}
        for entry in json.loads(res.stdout):
            key_bytes = parse_hex_array(entry["key"])
            val_bytes = parse_hex_array(entry["value"])

            if len(key_bytes) < 20:
                continue

            # Layout: src_ip(4) dst_ip(4) src_port(2) dst_port(2) protocol(1) pad(3) pkt_id(4)
            src_ip  = socket.inet_ntoa(key_bytes[0:4])
            dst_ip  = socket.inet_ntoa(key_bytes[4:8])
            src_port, dst_port = struct.unpack("<HH", key_bytes[8:12])
            protocol = key_bytes[12]          # __u8, no need unpack
            # key_bytes[13:16] = padding, skip
            pkt_id, = struct.unpack("<I", key_bytes[16:20])

            ts_val, = struct.unpack("<Q", val_bytes)

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol, pkt_id)
            parsed_map[flow_key] = ts_val

        return parsed_map
    except Exception as e:
        print(f"[WARN] fetch_map({map_path}) failed: {e}")
        return {}

def format_flow(src_ip, dst_ip, src_port, dst_port, protocol, pkt_id):
    proto_name = "TCP" if protocol == IPPROTO_TCP else "UDP"
    id_label   = "Seq" if protocol == IPPROTO_TCP else "IP_ID"
    return (f"{proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            f" | {id_label}: {pkt_id}")

flow_stats = defaultdict(lambda: {"count": 0, "total_ns": 0, "max_ns": 0})

print("Polling eBPF maps for Sojourn Time (Ctrl+C to stop)...")
seen_keys = set()

#Clean old data in eBPF maps
egress_data_init  = fetch_map("/sys/fs/bpf/tc/globals/egress_ts_map")
ingress_data_init = fetch_map("/sys/fs/bpf/tc/globals/ingress_ts_map")
for flow_key in ingress_data_init:
    if flow_key in egress_data_init:
        seen_keys.add(flow_key)
##
while True:
    egress_data  = fetch_map("/sys/fs/bpf/tc/globals/egress_ts_map")
    ingress_data = fetch_map("/sys/fs/bpf/tc/globals/ingress_ts_map")

    for flow_key, in_ts in ingress_data.items():
        if flow_key not in egress_data or flow_key in seen_keys:
            continue

        out_ts = egress_data[flow_key]
        if out_ts <= in_ts:
            continue  # stale entry

        src_ip, dst_ip, src_port, dst_port, protocol, pkt_id = flow_key
        sojourn_ns = out_ts - in_ts

        # Update stats
        stat_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        s = flow_stats[stat_key]
        s["count"]    += 1
        s["total_ns"] += sojourn_ns
        s["max_ns"]    = max(s["max_ns"], sojourn_ns)
        mean_us = (s["total_ns"] / s["count"]) / 1000.0
        max_us  = s["max_ns"] / 1000.0

        print(f"  {format_flow(*flow_key)}"
              f"  Sojourn: {sojourn_ns/1000:.2f} µs | "
              f"Mean: {mean_us:.2f} µs | Max: {max_us:.2f} µs")
        # print(f"  Sojourn: {sojourn_ns/1000:.2f} µs | "
        #       f"Mean: {mean_us:.2f} µs | Max: {max_us:.2f} µs\n")

        seen_keys.add(flow_key)

    if len(seen_keys) > 10000:
        active_keys = set(ingress_data.keys()) | set(egress_data.keys())
        seen_keys &= active_keys # Keep only active keys to prevent unbounded growth

    time.sleep(1)