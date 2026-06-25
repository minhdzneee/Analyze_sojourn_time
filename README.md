# eBPF TC Sojourn Time and Queue Backlog Analysis

This project measures **packet sojourn time** and **queue backlog** in the Linux networking stack using eBPF Traffic Control (TC), IFB, HTB, and `prio` qdisc.

The main experiment is to evaluate whether a flow assigned to a higher-priority qdisc class has lower queue backlog and lower sojourn time than a regular flow under bottleneck conditions.

## Highlights

- TC ingress and egress eBPF programs for packet-level timing.
- In-kernel sojourn-time calculation at egress.
- UDP packet matching using an ingress-generated `skb->mark` sequence instead of IPv4 `IP_ID`.
- IFB-based queueing pipeline for controlled bottleneck experiments.
- HTB + `prio` + per-class `pfifo` qdisc setup.
- Python tools for collecting logs and plotting sojourn time/backlog.
- Two deployment paths:
  - the author's Raspberry Pi / forwarding-node lab setup;
  - a generic local Linux setup that other users can run after cloning the repository.

## Project Structure

```text
.
├── README.md
├── .gitignore
├── cls_dt.h
├── cls_dt_ingress.c
├── cls_dt_ingress_ifb.c
├── cls_dt_egress.c
├── sojourn_monitor.py
├── analyze_sojourn.py
├── plot_backlog.py
├── check_backlog.sh
├── deploy_cls.sh
├── pi_deploy_cls_ifb.sh
├── pi_deploy_cls.sh
└── test.sh
```

## File Overview

| File | Purpose |
| --- | --- |
| `cls_dt.h` | Shared eBPF definitions: structs, map sizes, debug flags, UDP mark constants, and map schemas. |
| `cls_dt_ingress.c` | Basic ingress classifier used by the local deployment path. |
| `cls_dt_ingress_ifb.c` | IFB-oriented ingress classifier used by the author's priority/backlog lab. It records ingress timestamps, generates UDP sequence IDs, sets `skb->mark`, assigns `skb->priority`, and redirects packets to IFB. |
| `cls_dt_egress.c` | Egress TC program. It matches packets with ingress timestamps, computes sojourn time in-kernel, updates counters, and writes per-packet samples. |
| `sojourn_monitor.py` | Userspace monitor that reads pinned eBPF maps and prints per-packet sojourn logs. |
| `analyze_sojourn.py` | Parses monitor logs, filters UDP traffic, exports formatted CSV files, and plots sojourn-time trends. |
| `check_backlog.sh` | Captures repeated `tc -s -d qdisc/class show` snapshots for queue backlog analysis. |
| `plot_backlog.py` | Parses backlog snapshots and plots class backlog over the active test window. |
| `pi_deploy_cls_ifb.sh` | Remote deployment script for the author's Pi/forwarding-node IFB + HTB + `prio` setup. |
| `deploy_cls.sh` | Simple local deployment script for users who want to attach the eBPF programs directly to one Linux interface. |
| `pi_deploy_cls.sh` | Older remote deployment script kept for reference. The current priority/backlog path uses `pi_deploy_cls_ifb.sh`. |
| `test.sh` | Example `iperf3` script for two parallel UDP flows. Edit IPs and bitrates before running. |

## How Sojourn Time Is Measured

In this project:

```text
sojourn_time = egress_timestamp - ingress_timestamp
```

The ingress eBPF program stores an ingress timestamp for each tracked packet. The egress eBPF program looks up that timestamp, computes the sojourn time in-kernel, and writes a completed sample into `sojourn_sample_map`. The Python monitor only reads already-matched samples and prints them in a log format that can be plotted later.

For UDP, the project does not rely on IPv4 `IP_ID`, because it is only 16 bits and wraps quickly at high bitrate. Instead, the ingress program generates a per-flow sequence number and stores it in `skb->mark`. The egress program reads the mark to match the packet with its ingress timestamp.

## Requirements

### Linux / eBPF Tools

Install these on the machine that compiles or deploys the eBPF programs:

```text
clang
llvm
iproute2 / tc
bpftool
python3
python3-pip
ssh
scp
```

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install clang llvm iproute2 bpftool python3 python3-pip
```

The IFB experiment also requires IFB support on the forwarding node:

```bash
sudo modprobe ifb
```

On OpenWrt, the package is usually:

```bash
opkg update
opkg install kmod-ifb
```

Package names may vary by distribution.

### Python Plotting Packages

Install on the analysis machine:

```bash
pip install pandas matplotlib
```

## Deployment Modes

The repository has two intended ways to run the project.

## Mode 1: Author's Pi / Forwarding-Node Lab Setup

This is the main experimental setup used for priority and backlog measurements.

Main script:

```text
pi_deploy_cls_ifb.sh
```

### Lab Topology

```text
Sender
  -> ingress interface on Pi/forwarding node
  -> TC ingress eBPF
  -> redirect to ifb0
  -> HTB bottleneck
  -> prio qdisc
  -> TC egress eBPF
  -> egress interface on Pi/forwarding node
  -> Receiver(s)
```

Current default values in `pi_deploy_cls_ifb.sh`:

```text
EGRESS_IFACE = phy0-ap0
INGRESS_IFACE = eth0
PI_HOST      = root@192.168.3.2
IFB_IFACE    = ifb0
IFB_RATE     = 100mbit
LEAF_LIMIT   = 100 packets
```

These defaults match the author's lab. Users with a different topology should pass their own values as command-line arguments.

### Qdisc Pipeline

The intended IFB queueing pipeline is:

```text
ifb0
└── htb 10: root
    └── class htb 10:1 rate <IFB_RATE>
        └── prio 1: parent 10:1
            ├── class 1:1 -> pfifo 101
            ├── class 1:2 -> pfifo 102
            └── class 1:3 -> pfifo 103
```

The priority classifier maps:

```text
priority destination -> class 1:1
all other traffic    -> class 1:3
```

### Configure The Priority Destination

Edit `cls_dt_ingress_ifb.c`:

```c
static const __u32 priority_dst_ip = bpf_htonl(IP4(192, 168, 3, 122));
```

This destination IP is mapped to class `1:1`.

Current classification logic:

```text
dst_ip == priority_dst_ip -> skb->priority = 0x10001 -> class 1:1
any other destination     -> skb->priority = 0x10003 -> class 1:3
```

### Deploy To The Pi / Forwarding Node

Run from the machine containing this repository:

```bash
./pi_deploy_cls_ifb.sh phy0-ap0 eth0 root@192.168.3.2 ifb0 100mbit 100
```

Arguments:

```text
phy0-ap0          egress interface
eth0              ingress interface
root@192.168.3.2  SSH target of the Pi/forwarding node
ifb0              IFB interface
100mbit           HTB bottleneck rate
100               pfifo limit per class, in packets
```

For another topology:

```bash
./pi_deploy_cls_ifb.sh <EGRESS_IFACE> <INGRESS_IFACE> <USER@HOST> <IFB_IFACE> <IFB_RATE> <LEAF_LIMIT>
```

Example:

```bash
./pi_deploy_cls_ifb.sh wlan0 eth0 root@10.0.0.1 ifb0 50mbit 200
```

### Verify The Qdisc Tree

On the Pi/forwarding node:

```bash
tc -s -d qdisc show dev ifb0
tc -s -d class show dev ifb0
```

Expected output should include:

```text
qdisc htb 10: root
class htb 10:1 ... rate 100Mbit ...
qdisc prio 1: parent 10:1
qdisc pfifo 101: parent 1:1
qdisc pfifo 102: parent 1:2
qdisc pfifo 103: parent 1:3
class prio 1:1
class prio 1:2
class prio 1:3
```

If you only see:

```text
qdisc prio 1: root
```

the HTB bottleneck is not active. In that case, backlog will usually remain close to zero and the priority experiment is not valid.

### Run The Sojourn Monitor

On the Pi/forwarding node:

```bash
python3 /root/sojourn_monitor.py > cls_htb_run.csv
```

Start the monitor before starting the traffic test. The monitor captures counter baselines at startup, so `In`, `Eg`, and `Drop` are calculated for the current test window.

### Run The Backlog Monitor

Copy the script to the Pi if needed:

```bash
scp check_backlog.sh root@192.168.3.2:~/
ssh root@192.168.3.2
chmod +x ~/check_backlog.sh
```

Run:

```bash
./check_backlog.sh ifb0 0.1 cls_htb_check_backlog.csv
```

The output file should contain:

```text
OK_HTB_TREE: htb 10: root -> prio 1: parent 10:1
```

### Generate Traffic

Start an `iperf3` server on each receiver:

```bash
iperf3 -s -p 5201
```

From the sender, run two UDP flows in parallel:

```bash
iperf3 -c <PRIORITY_DST_IP> -u -b 80M -l 1400 -t 30 &
PID1=$!

iperf3 -c <DEFAULT_DST_IP> -u -b 80M -l 1400 -t 30 &
PID2=$!

wait $PID1 $PID2
```

If the HTB rate is `100mbit`, the combined `80M + 80M` traffic exceeds the bottleneck and backlog should build up.

## Mode 2: Generic Local Linux Deployment

This mode is for users who clone the repository and want to run a simpler local measurement on their own Linux machine.

Main script:

```text
deploy_cls.sh
```

This mode:

- compiles `cls_dt_ingress.c` and `cls_dt_egress.c`;
- attaches eBPF programs to the `clsact` qdisc of one interface;
- does not create IFB;
- does not create an HTB bottleneck;
- is suitable for basic sojourn-time measurement on a local interface.

Run:

```bash
sudo ./deploy_cls.sh <IFACE>
```

Example:

```bash
sudo ./deploy_cls.sh eth0
```

If no interface is passed, the script defaults to `eth0`.

After deployment:

```bash
sudo python3 sojourn_monitor.py > local_sojourn_run.csv
```

Check TC filters:

```bash
sudo tc -s filter show dev <IFACE> ingress
sudo tc -s filter show dev <IFACE> egress
```

If a user wants to reproduce the full priority/backlog experiment, they should use `pi_deploy_cls_ifb.sh` as a reference and adapt the remote host, interfaces, IFB device, and qdisc parameters to their topology.

## Analysis Workflow

The analysis tools can be used with logs from either deployment mode.

### Plot Sojourn Time

Run:

```bash
python3 analyze_sojourn.py
```

The script prompts for:

```text
CLS file
No-CLS file, optional
UDP destination port, default 5201
Flow 1 source/destination IP
Flow 2 source/destination IP
Priority flow, 1 or 2
Moving-average window
Packet range, optional
```

Output directory:

```text
output_YYYYMMDD_HHMMSS/
```

Typical outputs:

- a copy of the original log file;
- a formatted UDP-only CSV;
- a sojourn-time plot with packet index on the X axis;
- a sojourn-time plot with ingress timestamp on the X axis, if `InTS` exists in the log.

### Plot Queue Backlog

Use this for files generated by `check_backlog.sh`.

Moving average:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 200 --x-axis sample
```

Raw line graph:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 0 --x-axis sample
```

Time-based X axis:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 200 --x-axis time
```

Output directory:

```text
output_<input_file_name>/
```

Active-window logic:

```text
start = first sample where class 1:1 sent-packet counter increases
end   = last sample where class 1:1 sent-packet counter still increases
```

This is intentional: class `1:1` is the class of the priority flow, while class `1:3` may still receive background traffic after the priority flow ends.

## Interpreting Results

When strict priority is working under a bottleneck:

```text
class 1:1:
  lower backlog
  lower p95 backlog
  lower or zero drops
  lower sojourn time

class 1:3:
  higher backlog
  may hit queue limit
  may drop many packets
  higher sojourn time
```

`prio` is strict priority. It can strongly favor class `1:1` and starve class `1:3`. If the goal is fairness, compare this setup with explicit HTB class rates, `fq_codel`, `cake`, or another scheduler.

## In, Eg, Drop

In `sojourn_monitor.py` logs:

```text
In   = packets from the flow seen at ingress since monitor startup
Eg   = packets from the flow seen at egress since monitor startup
Drop = In - Eg
```

Do not subtract arbitrary raw `tc` counters from unrelated time windows. TC counters are cumulative and may include traffic outside the test.

## Common Problems

### Only `qdisc prio 1: root` appears

The HTB bottleneck is not active. Redeploy with `pi_deploy_cls_ifb.sh` and make sure the IFB rate is not `0` or `none`.

### Backlog stays close to zero

Possible causes:

- the HTB tree is not active;
- total traffic does not exceed the IFB rate;
- traffic does not pass through the expected node/interface;
- packets are not redirected to IFB;
- the real bottleneck is somewhere else in the path.

### `sojourn_monitor.py` prints no packets

Check:

```bash
tc -s filter show dev <INGRESS_IFACE> ingress
tc -s filter show dev <EGRESS_IFACE> egress
bpftool map dump pinned /sys/fs/bpf/tc/globals/sojourn_debug_map
```

Useful debug counters:

```text
egress_udp       UDP packets reached the egress hook
udp_mark_ok      egress saw a valid ingress-generated skb->mark
ingress_ts_hit   egress found the ingress timestamp
sample_update    egress wrote a sojourn sample
```

### DEBUG_PRINT changes the result

`DEBUG_PRINT=1` uses `bpf_trace_printk`, which is slow and can artificially increase backlog.

For real measurements, keep this in `cls_dt.h`:

```c
#define DEBUG_PRINT 0
```

### TC counters do not reset

Qdisc/class counters are cumulative for the lifetime of the qdisc. Recreate the qdisc or redeploy to reset them.
