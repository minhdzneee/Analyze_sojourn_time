#!/bin/bash
set -euo pipefail

# Usage:
#   ./pi_deploy_cls_ifb.sh [EGRESS_IFACE] [INGRESS_IFACE] [PI_HOST] [IFB_IFACE] [IFB_RATE] [LEAF_LIMIT]
# Example:
#   ./pi_deploy_cls_ifb.sh phy0-ap0 eth0 root@192.168.3.2 ifb0
#   ./pi_deploy_cls_ifb.sh phy0-ap0 eth0 root@192.168.3.2 ifb0 100mbit 1000
#
# Traffic model:
#   Without IFB_RATE:
#     .103 -> eth0 ingress -> eBPF set priority + redirect -> ifb0 root prio -> stack -> phy0-ap0 egress
#   With IFB_RATE:
#     .103 -> eth0 ingress -> eBPF set priority + redirect -> ifb0 HTB 10:1 -> prio 1: -> stack -> phy0-ap0 egress

EGRESS_IFACE="${1:-phy0-ap0}"
INGRESS_IFACE="${2:-eth0}"
PI_HOST="${3:-root@192.168.3.2}"
IFB_IFACE="${4:-ifb0}"
IFB_RATE="${5:-${IFB_RATE:-100mbit}}"
IFB_LEAF_LIMIT="${6:-${IFB_LEAF_LIMIT:-100}}"

INGRESS_SRC="cls_dt_ingress.c"
# If you keep the IFB version under a different filename, use it automatically.
if [[ -f "cls_dt_ingress_ifb.c" ]]; then
    INGRESS_SRC="cls_dt_ingress_ifb.c"
fi

echo "[local] Ingress iface : $INGRESS_IFACE"
echo "[local] Egress iface  : $EGRESS_IFACE"
echo "[local] IFB iface     : $IFB_IFACE"
echo "[local] IFB rate      : ${IFB_RATE:-none}"
echo "[local] IFB leaf limit: $IFB_LEAF_LIMIT packets"
echo "[local] RP4 host      : $PI_HOST"
echo "[local] Ingress source: $INGRESS_SRC"

echo "[local] Compiling eBPF programs..."
clang -O2 -target bpf -g -c "$INGRESS_SRC" -o cls_dt_ingress.o
clang -O2 -target bpf -g -c cls_dt_egress.c -o cls_dt_egress.o

echo "[local] Copying object files to RP4..."
scp cls_dt_ingress.o cls_dt_egress.o sojourn_monitor.py "$PI_HOST":~/

echo "[rp4] Deploying TC/eBPF/IFB configuration..."
ssh "$PI_HOST" \
    "INGRESS_IFACE='$INGRESS_IFACE' EGRESS_IFACE='$EGRESS_IFACE' IFB_IFACE='$IFB_IFACE' IFB_RATE='$IFB_RATE' IFB_LEAF_LIMIT='$IFB_LEAF_LIMIT' bash -s" <<'REMOTE'
set -euo pipefail
chmod +x /root/sojourn_monitor.py 2>/dev/null || true

echo "[1/8] Ensuring BPF filesystem is mounted..."
mkdir -p /sys/fs/bpf/
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/ || true
mkdir -p /sys/fs/bpf/tc/globals

echo "[2/8] Preparing IFB interface..."
modprobe ifb 2>/dev/null || true
if ! ip link show "$IFB_IFACE" >/dev/null 2>&1; then
    if ! ip link add "$IFB_IFACE" type ifb 2>/dev/null; then
        echo "ERROR: Cannot create $IFB_IFACE. On OpenWrt, install/enable kmod-ifb." >&2
        echo "Try: opkg update && opkg install kmod-ifb" >&2
        exit 1
    fi
fi
ip link set dev "$IFB_IFACE" up
IFB_INDEX=$(cat "/sys/class/net/$IFB_IFACE/ifindex")
echo "[+] $IFB_IFACE ifindex = $IFB_INDEX"

echo "[3/8] Removing stale maps..."
rm -f /sys/fs/bpf/tc/globals/pkt_ts_map
rm -f /sys/fs/bpf/tc/globals/ingress_ts_map
rm -f /sys/fs/bpf/tc/globals/egress_ts_map
rm -f /sys/fs/bpf/tc/globals/ingress_count_map
rm -f /sys/fs/bpf/tc/globals/egress_count_map
rm -f /sys/fs/bpf/tc/globals/udp_seq_map
rm -f /sys/fs/bpf/tc/globals/sojourn_sample_map
rm -f /sys/fs/bpf/tc/globals/sojourn_debug_map
rm -f /sys/fs/bpf/tc/globals/ifb_ifindex_map

echo "[4/8] Flushing old trace logs..."
mkdir -p /sys/kernel/debug/tracing 2>/dev/null || true
ash -c 'echo > /sys/kernel/debug/tracing/trace' 2>/dev/null || true

echo "[5/8] Cleaning old qdisc/filter state..."
# clsact is where TC BPF programs attach.
tc qdisc del dev "$INGRESS_IFACE" clsact 2>/dev/null || true
tc qdisc del dev "$EGRESS_IFACE" clsact 2>/dev/null || true
# Remove old root qdiscs from previous experiments to avoid double priority queues.
tc qdisc del dev "$INGRESS_IFACE" root 2>/dev/null || true
tc qdisc del dev "$EGRESS_IFACE" root 2>/dev/null || true
tc qdisc del dev "$IFB_IFACE" root 2>/dev/null || true

if [[ -n "$IFB_RATE" && "$IFB_RATE" != "0" && "$IFB_RATE" != "none" ]]; then
    echo "[6/8] Creating IFB HTB rate limit ($IFB_RATE) + prio qdisc..."
    tc qdisc replace dev "$IFB_IFACE" root handle 10: htb default 1
    tc class replace dev "$IFB_IFACE" parent 10: classid 10:1 htb \
        rate "$IFB_RATE" ceil "$IFB_RATE" burst 64k cburst 64k
    tc qdisc replace dev "$IFB_IFACE" parent 10:1 handle 1: prio bands 3
else
    echo "[6/8] Creating IFB root prio qdisc..."
    tc qdisc replace dev "$IFB_IFACE" root handle 1: prio bands 3
fi

if [[ "$IFB_LEAF_LIMIT" != "0" && "$IFB_LEAF_LIMIT" != "none" ]]; then
    echo "[6/8] Creating per-band pfifo queues (limit $IFB_LEAF_LIMIT packets)..."
    tc qdisc replace dev "$IFB_IFACE" parent 1:1 handle 101: pfifo limit "$IFB_LEAF_LIMIT"
    tc qdisc replace dev "$IFB_IFACE" parent 1:2 handle 102: pfifo limit "$IFB_LEAF_LIMIT"
    tc qdisc replace dev "$IFB_IFACE" parent 1:3 handle 103: pfifo limit "$IFB_LEAF_LIMIT"
fi

echo "[7/8] Attaching eBPF programs..."
tc qdisc replace dev "$INGRESS_IFACE" clsact
tc qdisc replace dev "$EGRESS_IFACE" clsact

tc filter replace dev "$INGRESS_IFACE" ingress bpf da obj /root/cls_dt_ingress.o sec classifier
tc filter replace dev "$EGRESS_IFACE" egress  bpf da obj /root/cls_dt_egress.o  sec egress

echo "[8/8] Updating ifb_ifindex_map..."
hex_le32() {
    local v=$1
    printf "%02x %02x %02x %02x" \
        $(( v        & 255 )) \
        $(((v >> 8)  & 255 )) \
        $(((v >> 16) & 255 )) \
        $(((v >> 24) & 255 ))
}
IFB_HEX=$(hex_le32 "$IFB_INDEX")

bpftool map update pinned /sys/fs/bpf/tc/globals/ifb_ifindex_map \
    key hex 00 00 00 00 \
    value hex $IFB_HEX

echo "Deployment successful."
if [[ -n "$IFB_RATE" && "$IFB_RATE" != "0" && "$IFB_RATE" != "none" ]]; then
    echo "Pipeline: $INGRESS_IFACE ingress -> eBPF priority+redirect -> $IFB_IFACE HTB 10:1 rate $IFB_RATE -> prio 1: -> stack -> $EGRESS_IFACE egress"
else
    echo "Pipeline: $INGRESS_IFACE ingress -> eBPF priority+redirect -> $IFB_IFACE prio 1: -> stack -> $EGRESS_IFACE egress"
fi
echo
echo "Check IFB qdisc counters:"
echo "  tc -s class show dev $IFB_IFACE"
echo "  tc -s qdisc show dev $IFB_IFACE"
echo
echo "Current IFB qdisc/class tree:"
tc -s -d qdisc show dev "$IFB_IFACE" || true
tc -s -d class show dev "$IFB_IFACE" || true
echo
echo "Check egress timestamp hook:"
echo "  tc -s filter show dev $EGRESS_IFACE egress"
echo
echo "Print egress-computed per-packet sojourn samples in old log format:"
echo "  python3 /root/sojourn_monitor.py"
echo
echo "View trace logs:"
echo "  cat /sys/kernel/debug/tracing/trace_pipe"
REMOTE
