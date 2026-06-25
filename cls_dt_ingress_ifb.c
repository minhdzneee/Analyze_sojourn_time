#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#include "cls_dt.h"
// Target IP for Fast-Path Forwarding
static const __u32 target_ip = bpf_htonl(IP4(192, 168, 0, 162));

// Destination machine that should receive high priority during this test
static const __u32 priority_dst_ip = bpf_htonl(IP4(192, 168, 3, 122));

#if INDIVIDUAL_PACKET_TRACING

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SOJOURN_TS_MAP_MAX_ENTRIES);
    __type(key, struct pkt_id);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_ts_map SEC(".maps");

// Per-flow packet counter at ingress: In
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SOJOURN_FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_count_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_count_map SEC(".maps");

// Per-flow UDP sequence used only for packet matching. This avoids IPv4 IP_ID
// wrap/collision at high bitrate.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, SOJOURN_FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_count_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_seq_map SEC(".maps");

static __always_inline void inc_ingress_count(struct flow_count_key *key)
{
    __u64 init_val = 1;
    __u64 *cnt = bpf_map_lookup_elem(&ingress_count_map, key);

    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        bpf_map_update_elem(&ingress_count_map, key, &init_val, BPF_ANY);
    }
}

static __always_inline __u32 next_udp_seq(struct flow_count_key *key)
{
    __u64 init_val = 0;
    bpf_map_update_elem(&udp_seq_map, key, &init_val, BPF_NOEXIST);

    __u64 *cnt = bpf_map_lookup_elem(&udp_seq_map, key);
    if (!cnt)
        return 0;

    __u64 seq64 = *cnt + 1;
    __u32 seq = (__u32)(seq64 & SOJOURN_SEQ_COUNTER_MASK);

    if (seq == 0) {
        seq = 1;
        seq64++;
    }

    *cnt = seq64;

    __u32 cpu_id = bpf_get_smp_processor_id() & SOJOURN_CPU_ID_MASK;
    return (cpu_id << SOJOURN_CPU_SHIFT) | seq;
}

#endif

// IFB redirect target. User-space deploy script writes ifb0 ifindex here.
// The ingress program uses this after setting skb->priority so packets pass
// through ifb0 root prio qdisc before continuing to the normal stack.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifb_ifindex_map SEC(".maps");

// eBPF Map to store the timestamp of the last processed packet for IAT calculation
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SOJOURN_FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_id);
    __type(value, struct flow_state);
} last_ts_map_for_IAT SEC(".maps");

SEC("classifier")
int classify_flow(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. Ethernet Header Check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only continue to process IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2. IP Header Check
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 len = skb->len;
    __u16 src_port = 0;
    __u16 dest_port = 0;
    __u8 is_tcp = 0;
    __u32 tcp_seq = 0;
    __u32 tcp_ack = 0;
    __u8 tcp_flags = 0;
    __u8 counted_packet = 0;

    // 3. Layer 4 Header Check (TCP/UDP)
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);

        if ((void *)(tcp + 1) > data_end) {
            return TC_ACT_OK;
        }

        is_tcp = 1;
        src_port = bpf_ntohs(tcp->source);
        dest_port = bpf_ntohs(tcp->dest);
        tcp_seq = bpf_ntohl(tcp->seq);
        tcp_ack = bpf_ntohl(tcp->ack_seq);
        tcp_flags = ((__u8 *)tcp)[13];

#if INDIVIDUAL_PACKET_TRACING
        // Record Ingress Timestamp for Python Sojourn Calculation (TCP)
        struct pkt_id pkt_key = {};
        pkt_key.src_ip = iph->saddr;
        pkt_key.dst_ip = iph->daddr;
        pkt_key.src_port = src_port;
        pkt_key.dst_port = dest_port;
        pkt_key.protocol = IPPROTO_TCP;
        pkt_key.tcp_seq = tcp_seq;

        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&ingress_ts_map, &pkt_key, &ts, BPF_ANY);

        counted_packet = 1;
#endif

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);

        if ((void *)(udp + 1) > data_end) {
            return TC_ACT_OK;
        }

        src_port = bpf_ntohs(udp->source);
        dest_port = bpf_ntohs(udp->dest);

#if INDIVIDUAL_PACKET_TRACING
        // Record Ingress Timestamp for Python Sojourn Calculation (UDP)
        struct flow_count_key seq_key = {};
        seq_key.src_ip = iph->saddr;
        seq_key.dst_ip = iph->daddr;
        seq_key.src_port = src_port;
        seq_key.dst_port = dest_port;
        seq_key.protocol = IPPROTO_UDP;

        __u32 udp_seq = next_udp_seq(&seq_key);
        if (udp_seq != 0) {
            struct __sk_buff *volatile skb_ptr = skb;
            skb_ptr->mark = SOJOURN_MARK_MAGIC | udp_seq;

            struct pkt_id pkt_key = {};
            pkt_key.src_ip = iph->saddr;
            pkt_key.dst_ip = iph->daddr;
            pkt_key.src_port = src_port;
            pkt_key.dst_port = dest_port;
            pkt_key.protocol = IPPROTO_UDP;
            pkt_key.udp_seq = udp_seq;

            __u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&ingress_ts_map, &pkt_key, &ts, BPF_ANY);

            counted_packet = 1;
        }
#endif
    }

#if INDIVIDUAL_PACKET_TRACING
    // Count every TCP/UDP packet observed at ingress.
    // This is the "In" value for a real traffic flow.
    if (counted_packet) {
        struct flow_count_key c_key = {};
        c_key.src_ip = iph->saddr;
        c_key.dst_ip = iph->daddr;
        c_key.src_port = src_port;
        c_key.dst_port = dest_port;
        c_key.protocol = iph->protocol;
        inc_ingress_count(&c_key);
    }
#endif

    // 4. Calculate Inter-Arrival Time (IAT) per flow
    __u64 current_ts = bpf_ktime_get_ns();
    __u64 iat_ns = 0;
    __u64 mean_fiat_ns = 0;
    __u64 max_fiat_ns = 0;

    struct flow_id f_key = {};
    f_key.src_ip = iph->saddr;
    f_key.dst_ip = iph->daddr;
    f_key.src_port = src_port;
    f_key.dst_port = dest_port;

    struct flow_state *state = bpf_map_lookup_elem(&last_ts_map_for_IAT, &f_key);
    if (state) {
        iat_ns = current_ts - state->last_ts;
        state->last_ts = current_ts;
        state->sum_iat_ns += iat_ns;
        if (iat_ns > state->max_iat_ns) {
            state->max_iat_ns = iat_ns;
        }
        state->packet_count++;
        if (state->packet_count > 1) {
            mean_fiat_ns = state->sum_iat_ns / (state->packet_count - 1);
        }
        max_fiat_ns = state->max_iat_ns;
    } else {
        struct flow_state new_state = {
            .last_ts = current_ts,
            .sum_iat_ns = 0,
            .max_iat_ns = 0,
            .packet_count = 1,
        };
        bpf_map_update_elem(&last_ts_map_for_IAT, &f_key, &new_state, BPF_ANY);
    }

#if DEBUG_PRINT
    char dbg_fmt[] = "[INNN] len: %u, port: %u, IAT: %llu ns\n";
    bpf_trace_printk(dbg_fmt, sizeof(dbg_fmt), len, dest_port, iat_ns);

    if (is_tcp) {
        char tcp_fmt[] = "[INNN] TCP Seq: %u, Ack: %u, Flags: 0x%x\n";
        bpf_trace_printk(tcp_fmt, sizeof(tcp_fmt), tcp_seq, tcp_ack, tcp_flags);
    }
#endif

#if INDIVIDUAL_PACKET_TRACING
    // --- Fast-Path Forwarding (Bypass Local Stack) ---
    // If you are only testing priority classification, make sure your test packets
    // do not match target_ip, or this return will bypass the priority logic below.
    if (iph->saddr == target_ip) {
#if DEBUG_PRINT
        char fwd_fmt[] = "[INNN] Fast-forwarding intercepted IP: 0x%x\n";
        bpf_trace_printk(fwd_fmt, sizeof(fwd_fmt), bpf_ntohl(iph->saddr));
#endif

        unsigned char tmp_mac[6];
#pragma unroll
        for (int i = 0; i < 6; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        return bpf_redirect(skb->ifindex, 0);
    }
#endif

    // 5. Priority classifier for one destination machine.
    // Test goal:
    //   dst_ip == 192.168.3.122 -> class 1:1, high priority
    //   other destinations        -> class 1:3, lower/default priority
    if (iph->daddr == priority_dst_ip) {
        struct __sk_buff *volatile skb_ptr = skb;
        skb_ptr->priority = 0x10001; // Class 1:1, high priority
#if DEBUG_PRINT
        char fmt[] = "[INNN] Priority destination detected! Assigned class 1:1\n";
        bpf_trace_printk(fmt, sizeof(fmt));
#endif
    } else {
        struct __sk_buff *volatile skb_ptr = skb;
        skb_ptr->priority = 0x10003; // Class 1:3, lower/default priority
#if DEBUG_PRINT
        char fmt[] = "[INNN] Regular destination. Assigned class 1:3\n";
        bpf_trace_printk(fmt, sizeof(fmt));
#endif
    }

    // 6. Redirect to IFB so the packet goes through ifb0 root prio qdisc.
    // The deploy script writes ifb0 ifindex into ifb_ifindex_map[0].
    __u32 ifb_key = 0;
    __u32 *ifb_ifindex = bpf_map_lookup_elem(&ifb_ifindex_map, &ifb_key);
    if (ifb_ifindex && *ifb_ifindex) {
#if DEBUG_PRINT
        char ifb_fmt[] = "[INNN] Redirecting packet to IFB ifindex=%u\n";
        bpf_trace_printk(ifb_fmt, sizeof(ifb_fmt), *ifb_ifindex);
#endif
        return bpf_redirect(*ifb_ifindex, 0);
    }

#if DEBUG_PRINT
    char no_ifb_fmt[] = "[INNN] IFB ifindex not set, packet continues normally\n";
    bpf_trace_printk(no_ifb_fmt, sizeof(no_ifb_fmt));
#endif
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
