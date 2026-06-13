#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Default interface is eth0, but can be overridden via the first argument
# Usage: ./deploy_cls.sh [interface]
IFACE="${1:-eth0}"

echo "Starting eBPF deployment on interface: $IFACE"

echo "[0/4] Compiling eBPF C source code..."
clang -O2 -target bpf -g -c cls_dt_ingress.c -o cls_dt_ingress.o
clang -O2 -target bpf -g -c cls_dt_egress.c -o cls_dt_egress.o

echo "[1/4] Ensuring BPF filesystem is mounted..."
sudo mkdir -p /sys/fs/bpf/
sudo mount -t bpf bpf /sys/fs/bpf/ || true

echo "[+] Removing stale maps to allow structural changes..."
sudo rm -f /sys/fs/bpf/tc/globals/pkt_ts_map
sudo rm -f /sys/fs/bpf/tc/globals/ingress_ts_map
sudo rm -f /sys/fs/bpf/tc/globals/egress_ts_map

echo "[+] Flushing old trace logs..."
sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'

echo "[2/4] Replacing clsact qdisc..."
sudo tc qdisc replace dev "$IFACE" clsact

echo "[3/4] Attaching ingress eBPF program..."
sudo tc filter replace dev "$IFACE" ingress bpf da obj cls_dt_ingress.o sec classifier

echo "[4/4] Attaching egress eBPF program..."
sudo tc filter replace dev "$IFACE" egress bpf da obj cls_dt_egress.o sec egress

echo "Deployment successful!"
echo "View live trace logs with: sudo cat /sys/kernel/debug/tracing/trace_pipe"