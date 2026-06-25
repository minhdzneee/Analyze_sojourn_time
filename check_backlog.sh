#!/bin/sh

# Capture tc qdisc/class counters repeatedly for backlog analysis.
# Usage:
#   ./check_backlog.sh [iface] [interval_s] [output_file] [max_samples]
#
# Examples:
#   ./check_backlog.sh ifb0 0.1
#   ./check_backlog.sh ifb0 0.1 2026_06_25_cls_htb_check_backlog_80M_1400_2.csv
#   ./check_backlog.sh ifb0 0.1 2026_06_25_cls_htb_check_backlog_80M_1400_2.csv 400

set -u

IFACE="${1:-ifb0}"
INTERVAL="${2:-0.1}"
OUT_FILE="${3:-}"
MAX_SAMPLES="${4:-0}"

usage() {
    echo "Usage: $0 [iface] [interval_s] [output_file] [max_samples]"
    echo "  iface       default: ifb0"
    echo "  interval_s  default: 0.1"
    echo "  output_file optional; if omitted, write to stdout"
    echo "  max_samples optional; 0 means run until Ctrl-C"
}

case "$IFACE" in
    -h|--help)
        usage
        exit 0
        ;;
esac

tree_status() {
    qdisc_text="$1"

    case "$qdisc_text" in
        *"qdisc htb 10:"*"qdisc prio 1: parent 10:1"*)
            echo "OK_HTB_TREE: htb 10: root -> prio 1: parent 10:1"
            ;;
        *"qdisc htb 10:"*)
            echo "WARN_PARTIAL_HTB_TREE: found htb 10:, but did not find prio 1: parent 10:1"
            ;;
        *"qdisc prio 1: root"*)
            echo "WARN_ROOT_PRIO_ONLY: found prio 1: root, HTB bottleneck is not active"
            ;;
        *)
            echo "WARN_UNKNOWN_TREE: did not find expected htb 10: tree"
            ;;
    esac
}

capture_loop() {
    SAMPLE=0

    echo "# check_backlog.sh"
    echo "# iface=$IFACE"
    echo "# interval_s=$INTERVAL"
    echo "# max_samples=$MAX_SAMPLES"
    echo "# expected_tree: ifb0 -> htb 10: root -> class 10:1 -> prio 1: parent 10:1 -> classes 1:1/1:2/1:3"
    echo "# start_time=$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)"
    echo

    while :; do
        SAMPLE=$((SAMPLE + 1))
        WALL_TIME="$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)"
        CLOCK_TIME="$(date '+%H:%M:%S')"
        QDISC_OUT="$(tc -s -d qdisc show dev "$IFACE" 2>&1)"
        CLASS_OUT="$(tc -s -d class show dev "$IFACE" 2>&1)"

        echo "===== SAMPLE $SAMPLE $WALL_TIME ====="
        echo "$CLOCK_TIME"
        echo "===== TREE CHECK $IFACE ====="
        tree_status "$QDISC_OUT"
        echo "===== QDISC $IFACE ====="
        echo "$QDISC_OUT"
        echo "===== CLASS $IFACE ====="
        echo "$CLASS_OUT"
        echo

        if [ "$MAX_SAMPLES" != "0" ] && [ "$SAMPLE" -ge "$MAX_SAMPLES" ]; then
            break
        fi

        sleep "$INTERVAL"
    done
}

if [ -n "$OUT_FILE" ]; then
    capture_loop | tee "$OUT_FILE"
else
    capture_loop
fi
