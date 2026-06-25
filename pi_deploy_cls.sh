#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Flow direction:
#   packet enters  : eth0
#   packet exits   : phy0-ap0
#
# Usage:
#   ./pi_deploy_cls.sh [egress_interface] [ingress_interface]
#
# Default:
#   EGRESS_IFACE  = phy0-ap0
#   INGRESS_IFACE = eth0

EGRESS_IFACE="${1:-phy0-ap0}"
INGRESS_IFACE="${2:-eth0}"
PI_HOST="root@192.168.3.2"

printf "Starting eBPF deployment\n"
printf "  Ingress interface: %s\n" "$INGRESS_IFACE"
printf "  Egress interface : %s\n" "$EGRESS_IFACE"
printf "  Raspberry Pi     : %s\n" "$PI_HOST"

printf "\n[1/6] Compiling eBPF C source code...\n"
clang -O2 -target bpf -g -c cls_dt_ingress.c -o cls_dt_ingress.o
clang -O2 -target bpf -g -c cls_dt_egress.c -o cls_dt_egress.o

printf "\n[2/6] Copying object files to Raspberry Pi...\n"
scp cls_dt_ingress.o cls_dt_egress.o sojourn_monitor.py "$PI_HOST:~/"

ssh "$PI_HOST" << EOF_REMOTE
set -e

EGRESS_IFACE="$EGRESS_IFACE"
INGRESS_IFACE="$INGRESS_IFACE"

cd ~
chmod +x /root/sojourn_monitor.py 2>/dev/null || true

printf "\n[3/6] Ensuring BPF filesystem is mounted...\n"
mkdir -p /sys/fs/bpf/
mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true

printf "\n[+] Removing stale pinned maps...\n"
rm -f /sys/fs/bpf/tc/globals/pkt_ts_map
rm -f /sys/fs/bpf/tc/globals/ingress_ts_map
rm -f /sys/fs/bpf/tc/globals/egress_ts_map
rm -f /sys/fs/bpf/tc/globals/ingress_count_map
rm -f /sys/fs/bpf/tc/globals/egress_count_map
rm -f /sys/fs/bpf/tc/globals/udp_seq_map
rm -f /sys/fs/bpf/tc/globals/sojourn_sample_map
rm -f /sys/fs/bpf/tc/globals/sojourn_stats_map

printf "\n[+] Flushing old trace logs...\n"
ash -c 'echo > /sys/kernel/debug/tracing/trace' 2>/dev/null || true

printf "\n[4/6] Replacing clsact qdisc...\n"
tc qdisc replace dev "\$INGRESS_IFACE" clsact
tc qdisc replace dev "\$EGRESS_IFACE" clsact

printf "\n[5/6] Attaching ingress eBPF program to ingress interface...\n"
tc filter replace dev "\$INGRESS_IFACE" ingress bpf da obj cls_dt_ingress.o sec classifier

printf "\n[6/6] Attaching egress eBPF program to egress interface...\n"
tc filter replace dev "\$EGRESS_IFACE" egress bpf da obj cls_dt_egress.o sec egress

printf "\n[+] Replacing root priority qdisc on egress interface...\n"
tc qdisc replace dev "\$EGRESS_IFACE" root handle 1: prio bands 3

printf "\nDeployment successful!\n"
printf "Ingress eBPF : %s ingress\n" "\$INGRESS_IFACE"
printf "Egress eBPF  : %s egress\n" "\$EGRESS_IFACE"
printf "Prio qdisc   : %s root handle 1:\n" "\$EGRESS_IFACE"
printf "\nView live trace logs with:\n"
printf "  cat /sys/kernel/debug/tracing/trace_pipe\n"
EOF_REMOTE
