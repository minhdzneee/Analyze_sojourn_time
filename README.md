# eBPF Sojourn Time Monitoring and Analysis

## Overview

This project uses eBPF traffic control (TC) programs to measure packet **sojourn time** inside the Linux networking stack.

The workflow consists of three main steps:

1. Deploy ingress and egress eBPF programs to a network interface.
2. Monitor packet timestamps and collect sojourn-time logs.
3. Analyze the collected logs and generate statistics and visualization graphs.

---

## Project Files

| File                 | Description                                                                     |
| -------------------- | ------------------------------------------------------------------------------- |
| `cls_dt_ingress.c`   | eBPF ingress classifier program                                                 |
| `cls_dt_egress.c`    | eBPF egress timestamp collector                                                 |
| `deploy_cls.sh`      | Deployment script for compiling and attaching eBPF programs                     |
| `sojourn_monitor.py` | Userspace monitoring tool that reads eBPF maps and computes packet sojourn time |
| `analyze_sojourn.py` | Analysis and visualization tool for collected sojourn logs                      |

---

## Prerequisites

### System Requirements

* Linux kernel with eBPF support
* `clang`
* `tc` (iproute2)
* `bpftool`
* Python 3.8+

### Python Dependencies

Install required packages:

```bash
pip install pandas matplotlib
```

---

## Step 1: Deploy eBPF Programs

Compile and attach the ingress and egress eBPF programs to the desired network interface.

### Usage

```bash
sudo ./deploy_cls.sh <interface>
```

Example:

```bash
sudo ./deploy_cls.sh eth0
```

If no interface is specified, the script uses:

```bash
eth0
```

### What the Script Does

The deployment script performs the following actions:

1. Compiles:

   ```text
   cls_dt_ingress.c
   cls_dt_egress.c
   ```

2. Mounts the BPF filesystem:

   ```text
   /sys/fs/bpf
   ```

3. Removes old pinned eBPF maps.

4. Clears kernel trace logs.

5. Replaces the existing `clsact` qdisc.

6. Attaches:

   * Ingress program (`classifier`)
   * Egress program (`egress`)

After successful deployment, the eBPF programs begin recording packet timestamps.

---

## Step 2: Collect Sojourn-Time Logs

Run the monitoring application:

```bash
sudo python3 sojourn_monitor.py
```

The program continuously reads:

```text
/sys/fs/bpf/tc/globals/ingress_ts_map
/sys/fs/bpf/tc/globals/egress_ts_map
```

and calculates:

```text
Sojourn Time = Egress Timestamp − Ingress Timestamp
```

Example output:

```text
TCP 192.168.3.10:5000 -> 192.168.3.123:5201 | Seq: 12345
Sojourn: 24.50 µs | Mean: 21.80 µs | Max: 38.10 µs
```

### Save Output to CSV-Compatible Log File

Redirect the console output to a file:

```bash
sudo python3 sojourn_monitor.py > cls_run.csv
```

or

```bash
sudo python3 sojourn_monitor.py > no_cls_run.csv
```

Stop logging with:

```bash
Ctrl + C
```

The resulting files will be used as input for the analysis stage.

---

## Step 3: Analyze Collected Logs

Run:

```bash
python3 analyze_sojourn.py
```

The script will interactively request:

### Input Files

Example:

```text
CLS file:
2026_06_09_cls_3.csv

No-CLS file:
2026_06_09_no_cls_3.csv
```

### Destination IPs

Example:

```text
Destination IP 1:
192.168.3.213

Destination IP 2:
192.168.3.123
```

### Priority Flow Information

Example:

```text
Priority IP:
192.168.3.123

Priority Description:
CLS High Priority
```

### Moving Average Window

Example:

```text
200
```

### Packet Range (Optional)

Example:

```text
Start packet:
0

End packet:
5000
```

---

## Analysis Output

For each execution, a new directory is automatically created:

```text
output_YYYYMMDD_HHMMSS/
```

Example:

```text
output_20260609_103522/
```

Generated artifacts include:

### Original Files

```text
cls_run.csv
no_cls_run.csv
```

### Reformatted CSV Files

```text
cls_run_formatted.csv
no_cls_run_formatted.csv
```

### Comparison Graph

```text
sojourn_comparison.png
```

or

```text
sojourn_comparison_zoom_START_END.png
```

### Summary Statistics

The script reports:

* Packet count
* Mean sojourn time
* Median sojourn time
* Maximum sojourn time
* Standard deviation

for each destination flow.

---

## Typical Workflow

### 1. Deploy eBPF programs

```bash
sudo ./deploy_cls.sh eth0
```

### 2. Start monitoring and collect logs

```bash
sudo python3 sojourn_monitor.py > cls_run.csv
```

### 3. Generate traffic

Run your traffic generator (iperf3, application workload, etc.).

### 4. Stop logging

```text
Ctrl + C
```

### 5. Analyze results

```bash
python3 analyze_sojourn.py
```

### 6. Review generated plots and statistics

Check the automatically created:

```text
output_*/
```

directory for CSV exports, graphs, and summary results.

---

## Notes

* Root privileges are required for eBPF deployment and monitoring.
* Ensure the ingress and egress programs are attached to the same network interface.
* The monitoring script only computes sojourn time when matching ingress and egress packet identifiers are found.
* Large traffic volumes may require increasing eBPF map sizes depending on workload characteristics.
