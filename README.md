# eBPF TC Sojourn Time and Queue Backlog Analysis

Du an nay dung eBPF Traffic Control (TC) de do **sojourn time** cua goi tin va quan sat **backlog** trong qdisc. Muc tieu chinh cua project la kiem tra xem khi dung `qdisc prio`, flow duoc gan uu tien cao co backlog/sojourn time nho hon flow thuong hay khong.

Project co hai cach trien khai:

1. **Lab/Pi setup cua tac gia**: dung `pi_deploy_cls_ifb.sh`, co IFB + HTB + prio, dung de test priority/backlog nhu trong qua trinh nghien cuu.
2. **May Linux cua nguoi dung khac**: dung `deploy_cls.sh`, attach eBPF truc tiep len mot interface tren may cua ho de do sojourn time co ban.

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
├── sojourn_stats_monitor.py
└── test.sh
```

## File Overview

| File | Vai tro |
| --- | --- |
| `cls_dt.h` | Header chung cho eBPF: struct key/value, map size, macro debug, macro UDP matching bang `skb->mark`. |
| `cls_dt_ingress.c` | Ingress eBPF ban co ban. Dung cho `deploy_cls.sh` khi trien khai truc tiep tren mot interface. |
| `cls_dt_ingress_ifb.c` | Ingress eBPF cho lab IFB. Ghi ingress timestamp, tao UDP sequence, gan `skb->mark`, gan `skb->priority`, redirect sang `ifb0`. |
| `cls_dt_egress.c` | Egress eBPF. Match packet voi ingress timestamp, tinh sojourn time trong kernel, ghi ket qua vao `sojourn_sample_map`. |
| `sojourn_monitor.py` | Chuong trinh userspace doc eBPF maps va in log sojourn theo tung packet. |
| `analyze_sojourn.py` | Parse log tu `sojourn_monitor.py`, loc UDP, ve do thi sojourn theo packet index va timestamp. |
| `check_backlog.sh` | Lay snapshot `tc -s -d qdisc/class show` theo thoi gian de do backlog. |
| `plot_backlog.py` | Parse output cua `check_backlog.sh` va ve do thi backlog cho class `1:1`, `1:3`. |
| `pi_deploy_cls_ifb.sh` | Script deploy cho setup Pi/forwarding node cua tac gia: remote deploy, IFB, HTB, prio, pfifo. |
| `deploy_cls.sh` | Script deploy don gian tren may Linux hien tai cua nguoi dung: compile + attach TC ingress/egress tren mot interface. |
| `pi_deploy_cls.sh` | Script remote deploy cu, khong phai duong khuyen nghi cho IFB/HTB hien tai. |
| `sojourn_stats_monitor.py` | Huong doc aggregate stats thu nghiem. Khong phai duong chinh de ve per-packet graph. |
| `test.sh` | Vi du chay 2 luong `iperf3`. Can sua IP/bitrate theo topology that. |

## What Is Sojourn Time?

Trong project nay:

```text
sojourn_time = egress_timestamp - ingress_timestamp
```

Ingress eBPF ghi timestamp khi packet di vao node do. Egress eBPF lookup timestamp do, tinh sojourn time, roi ghi sample ra map de Python doc.

## Required Packages

### Common Linux Packages

Can co tren may compile/deploy eBPF:

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

Tren Ubuntu/Debian co the cai gan dung nhu sau:

```bash
sudo apt update
sudo apt install clang llvm iproute2 bpftool python3 python3-pip
```

Tren forwarding node neu dung IFB:

```text
ifb kernel module
```

Thu lenh:

```bash
sudo modprobe ifb
```

Tren OpenWrt, package thuong can la:

```bash
opkg update
opkg install kmod-ifb
```

Ten package co the khac nhau tuy distro.

### Python Packages For Analysis

Tren may dung de ve do thi:

```bash
pip install pandas matplotlib
```

## Mode 1: Lab/Pi Setup Cua Tac Gia

Day la mode dung trong qua trinh test priority/backlog cua tac gia.

Script chinh:

```text
pi_deploy_cls_ifb.sh
```

Mo hinh:

```text
Sender
  -> ingress interface tren Pi/forwarding node
  -> ingress eBPF
  -> redirect sang ifb0
  -> HTB bottleneck
  -> prio qdisc
  -> egress interface tren Pi/forwarding node
  -> Receiver(s)
```

Gia tri mac dinh trong script hien tai:

```text
EGRESS_IFACE = phy0-ap0
INGRESS_IFACE = eth0
PI_HOST      = root@192.168.3.2
IFB_IFACE    = ifb0
IFB_RATE     = 100mbit
LEAF_LIMIT   = 100 packets
```

Day la gia tri phu hop voi lab cua tac gia. Nguoi khac co the thay bang tham so khi chay script.

### Configure Priority Destination

Sua trong `cls_dt_ingress_ifb.c`:

```c
static const __u32 priority_dst_ip = bpf_htonl(IP4(192, 168, 3, 122));
```

Dong nay quy dinh destination IP nao duoc vao class `1:1`.

Logic hien tai:

```text
dst_ip == priority_dst_ip -> skb->priority = 0x10001 -> class 1:1
dst_ip khac               -> skb->priority = 0x10003 -> class 1:3
```

### Deploy On Pi / Forwarding Node

Chay tu may co source code:

```bash
./pi_deploy_cls_ifb.sh phy0-ap0 eth0 root@192.168.3.2 ifb0 100mbit 100
```

Y nghia tham so:

```text
phy0-ap0          egress interface
eth0              ingress interface
root@192.168.3.2  SSH target cua Pi/forwarding node
ifb0              IFB interface
100mbit           HTB bottleneck rate
100               pfifo limit moi class, don vi packet
```

Neu muon test voi cau hinh khac:

```bash
./pi_deploy_cls_ifb.sh <EGRESS_IFACE> <INGRESS_IFACE> <USER@HOST> <IFB_IFACE> <IFB_RATE> <LEAF_LIMIT>
```

Vi du:

```bash
./pi_deploy_cls_ifb.sh wlan0 eth0 root@10.0.0.1 ifb0 50mbit 200
```

### Expected Qdisc Tree

Sau deploy, tren Pi/forwarding node:

```bash
tc -s -d qdisc show dev ifb0
tc -s -d class show dev ifb0
```

Can thay:

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

Neu chi thay:

```text
qdisc prio 1: root
```

thi HTB bottleneck chua hoat dong. Luc nay backlog thuong gan 0 va ket qua khong phan anh dung bai test priority.

### Run Sojourn Monitor

Tren Pi/forwarding node:

```bash
python3 /root/sojourn_monitor.py > cls_htb_run.csv
```

Nen chay monitor truoc khi bat dau traffic test. Monitor lay counter baseline luc start, nen `In/Eg/Drop` se tinh theo cua so test.

### Run Backlog Monitor

Copy script sang Pi neu chua co:

```bash
scp check_backlog.sh root@192.168.3.2:~/
ssh root@192.168.3.2
chmod +x ~/check_backlog.sh
```

Chay:

```bash
./check_backlog.sh ifb0 0.1 cls_htb_check_backlog.csv
```

Trong file output can thay:

```text
OK_HTB_TREE: htb 10: root -> prio 1: parent 10:1
```

### Generate Traffic

Tren receiver:

```bash
iperf3 -s -p 5201
```

Tren sender, chay 2 UDP flows song song:

```bash
iperf3 -c <PRIORITY_DST_IP> -u -b 80M -l 1400 -t 30 &
PID1=$!

iperf3 -c <DEFAULT_DST_IP> -u -b 80M -l 1400 -t 30 &
PID2=$!

wait $PID1 $PID2
```

Neu HTB rate la `100mbit`, tong `80M + 80M` se vuot bottleneck va backlog se tang.

## Mode 2: Deploy Tren May Linux Cua Nguoi Dung

Day la mode don gian hon, dung cho nguoi khac clone repo va chay truc tiep tren may Linux cua ho.

Script chinh:

```text
deploy_cls.sh
```

Mode nay:

- Compile `cls_dt_ingress.c` va `cls_dt_egress.c`.
- Attach eBPF vao `clsact` cua mot interface.
- Khong tao IFB.
- Khong tao HTB bottleneck.
- Phu hop de do sojourn time co ban tren interface cua may do.

Chay:

```bash
sudo ./deploy_cls.sh <IFACE>
```

Vi du:

```bash
sudo ./deploy_cls.sh eth0
```

Neu khong truyen interface, script mac dinh dung:

```text
eth0
```

Sau deploy:

```bash
sudo python3 sojourn_monitor.py > local_sojourn_run.csv
```

Kiem tra TC filters:

```bash
sudo tc -s filter show dev <IFACE> ingress
sudo tc -s filter show dev <IFACE> egress
```

Luu y: neu nguoi dung muon test backlog/priority nhu lab IFB, ho nen dung `pi_deploy_cls_ifb.sh` lam mau va thay interface/host theo topology cua ho, hoac tu tao qdisc IFB/HTB tuong tu tren may cua minh.

## Analyze Sojourn Logs

Dung cho ca hai mode.

Chay tren may co Python packages:

```bash
python3 analyze_sojourn.py
```

Script se hoi:

```text
CLS file
No-CLS file, co the Enter de skip
UDP destination port, mac dinh 5201
Flow 1 source/destination IP
Flow 2 source/destination IP
Priority flow, 1 hoac 2
Moving-average window
Packet range, optional
```

Output:

```text
output_YYYYMMDD_HHMMSS/
```

Trong output co:

- Ban copy file log goc.
- CSV da format/loc UDP.
- Do thi sojourn theo packet index.
- Do thi sojourn theo timestamp neu log co `InTS`.

## Analyze Backlog Logs

Dung cho file output tu `check_backlog.sh`.

Ve moving average:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 200 --x-axis sample
```

Ve raw line graph:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 0 --x-axis sample
```

Ve theo thoi gian:

```bash
python3 plot_backlog.py cls_htb_check_backlog.csv --window 200 --x-axis time
```

Output:

```text
output_<input_file_name>/
```

Logic active window:

```text
start = sample dau tien class 1:1 co sent pkt tang
end   = sample cuoi cung class 1:1 con sent pkt tang
```

Ly do: class `1:1` la class cua priority flow; class `1:3` co the con nhan background traffic sau khi priority flow da ket thuc.

## How To Read Results

Khi priority hoat dong dung duoi bottleneck:

```text
class 1:1:
  backlog thap hon
  p95 backlog thap hon
  drop thap hon hoac bang 0
  sojourn time thap hon

class 1:3:
  backlog cao hon
  co the cham queue limit
  co the drop nhieu
  sojourn time cao hon
```

Can nho: `prio` la strict priority. No uu tien class `1:1` rat manh va co the lam class `1:3` bi starvation. Neu muc tieu la fairness, can thu them HTB class rate rieng, `fq_codel`, `cake`, hoac qdisc khac.

## In, Eg, Drop

Trong log `sojourn_monitor.py`:

```text
In   = so packet flow do vao ingress ke tu luc monitor start
Eg   = so packet flow do ra egress ke tu luc monitor start
Drop = In - Eg
```

Khong nen lay counter `tc` global o hai thoi diem tuy y roi tru truc tiep, vi counter `tc` la cumulative va co the chua traffic ngoai bai test.

## Common Problems

### `qdisc prio 1: root` only

HTB bottleneck chua active. Can deploy lai bang `pi_deploy_cls_ifb.sh` voi IFB rate khac `0`/`none`.

### Backlog gan 0

Co the do:

- HTB tree chua active.
- Tong traffic chua vuot IFB rate.
- Traffic khong di qua dung node/interface.
- Packet khong redirect sang IFB.
- Bottleneck nam o noi khac.

### `sojourn_monitor.py` khong in packet nao

Kiem tra:

```bash
tc -s filter show dev <INGRESS_IFACE> ingress
tc -s filter show dev <EGRESS_IFACE> egress
bpftool map dump pinned /sys/fs/bpf/tc/globals/sojourn_debug_map
```

Mot vai counter huu ich:

```text
egress_udp       UDP da den egress hook
udp_mark_ok      egress doc duoc skb->mark hop le
ingress_ts_hit   egress lookup duoc ingress timestamp
sample_update    egress da ghi sojourn sample
```

### DEBUG_PRINT lam sai ket qua

`DEBUG_PRINT=1` dung `bpf_trace_printk`, rat cham va co the lam tang backlog nhan tao.

Khi do that nen de trong `cls_dt.h`:

```c
#define DEBUG_PRINT 0
```

### TC counter khong reset

Counter qdisc/class la cumulative theo vong doi qdisc. Muon reset thi recreate qdisc hoac deploy lai.

## GitHub Notes

Nen commit source code va script:

```text
README.md
.gitignore
cls_dt.h
cls_dt_ingress.c
cls_dt_ingress_ifb.c
cls_dt_egress.c
sojourn_monitor.py
analyze_sojourn.py
plot_backlog.py
check_backlog.sh
deploy_cls.sh
pi_deploy_cls_ifb.sh
pi_deploy_cls.sh
sojourn_stats_monitor.py
test.sh
```

Khong nen commit:

```text
output_*/
20xx_*.csv
__pycache__/
*.o
.DS_Store
*.pcap
*.log
```

Project da co `.gitignore` de bo qua cac file ket qua do va artifact pho bien.
