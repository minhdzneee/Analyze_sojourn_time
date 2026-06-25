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

#if INDIVIDUAL_PACKET_TRACING

// Reuse the ingress timestamp map created by the ingress object. The deploy
// script attaches ingress first, then egress, so the pinned map already exists.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SOJOURN_TS_MAP_MAX_ENTRIES);
    __type(key, struct pkt_id);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_ts_map SEC(".maps");

#if SOJOURN_STORE_EGRESS_TS
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SOJOURN_TS_MAP_MAX_ENTRIES);
    __type(key, struct pkt_id);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_ts_map SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SOJOURN_TS_MAP_MAX_ENTRIES);
    __type(key, struct pkt_id);
    __type(value, struct sojourn_sample);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sojourn_sample_map SEC(".maps");

// Per-flow packet counter at egress: Eg
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SOJOURN_FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_count_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SOJOURN_DBG_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sojourn_debug_map SEC(".maps");

static __always_inline void inc_debug_counter(__u32 key)
{
    __u64 *cnt = bpf_map_lookup_elem(&sojourn_debug_map, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

static __always_inline void inc_egress_count(struct flow_count_key *key)
{
    __u64 init_val = 1;
    __u64 *cnt = bpf_map_lookup_elem(&egress_count_map, key);

    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        bpf_map_update_elem(&egress_count_map, key, &init_val, BPF_ANY);
    }
}

#endif

SEC("egress")
int check_egress_priority(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Ethernet Header Check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only continue to process IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP Header Check
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

#if INDIVIDUAL_PACKET_TRACING
    inc_debug_counter(SOJOURN_DBG_EGRESS_IPV4);
#endif

    __u32 len = skb->len;
    __u16 dest_port = 0;
    __u8 is_tcp = 0;
    __u32 tcp_seq = 0;
    __u32 tcp_ack = 0;
    __u8 tcp_flags = 0;

    // Layer 4 Header Check (TCP/UDP)
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end) {
            return TC_ACT_OK;
        }

        is_tcp = 1;
        dest_port = bpf_ntohs(tcp->dest);
        tcp_seq = bpf_ntohl(tcp->seq);
        tcp_ack = bpf_ntohl(tcp->ack_seq);
        tcp_flags = ((__u8 *)tcp)[13];
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end) {
            return TC_ACT_OK;
        }

        dest_port = bpf_ntohs(udp->dest);
#if INDIVIDUAL_PACKET_TRACING
        inc_debug_counter(SOJOURN_DBG_EGRESS_UDP);
#endif
    }

#if DEBUG_PRINT
    char dbg_fmt[] = "[Egress] len: %u, port: %u, prio: %u\n";
    bpf_trace_printk(dbg_fmt, sizeof(dbg_fmt), len, dest_port, skb->priority);

    if (is_tcp) {
        char tcp_fmt[] = "[Egress] TCP Seq: %u, Ack: %u, Flg: 0x%x\n";
        bpf_trace_printk(tcp_fmt, sizeof(tcp_fmt), tcp_seq, tcp_ack, tcp_flags);
    }
#endif

#if INDIVIDUAL_PACKET_TRACING
    // Record Egress Timestamp for Python Sojourn Calculation
    struct pkt_id pkt_key = {};
    int record_packet = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(tcp + 1) <= data_end) {
            pkt_key.src_ip = iph->saddr;
            pkt_key.dst_ip = iph->daddr;
            pkt_key.src_port = bpf_ntohs(tcp->source);
            pkt_key.dst_port = bpf_ntohs(tcp->dest);
            pkt_key.protocol = IPPROTO_TCP;
            pkt_key.tcp_seq = bpf_ntohl(tcp->seq);
            record_packet = 1;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udp + 1) <= data_end) {
            __u32 mark = skb->mark;
            if ((mark & SOJOURN_MARK_MASK) == SOJOURN_MARK_MAGIC) {
                inc_debug_counter(SOJOURN_DBG_UDP_MARK_OK);
                __u32 udp_seq = mark & SOJOURN_SEQ_MASK;

                if (udp_seq != 0) {
                    pkt_key.src_ip = iph->saddr;
                    pkt_key.dst_ip = iph->daddr;
                    pkt_key.src_port = bpf_ntohs(udp->source);
                    pkt_key.dst_port = bpf_ntohs(udp->dest);
                    pkt_key.protocol = IPPROTO_UDP;
                    pkt_key.udp_seq = udp_seq;
                    record_packet = 1;
                }
            } else {
                inc_debug_counter(SOJOURN_DBG_UDP_MARK_BAD);
            }
        }
    }

    if (record_packet) {
        inc_debug_counter(SOJOURN_DBG_RECORD_PACKET);
        __u64 ts = bpf_ktime_get_ns();
#if SOJOURN_STORE_EGRESS_TS
        bpf_map_update_elem(&egress_ts_map, &pkt_key, &ts, BPF_ANY);
#endif

        // Count every TCP/UDP packet observed at egress.
        // This is the "Eg" value for a real traffic flow.
        struct flow_count_key c_key = {};
        c_key.src_ip = pkt_key.src_ip;
        c_key.dst_ip = pkt_key.dst_ip;
        c_key.src_port = pkt_key.src_port;
        c_key.dst_port = pkt_key.dst_port;
        c_key.protocol = pkt_key.protocol;
        inc_egress_count(&c_key);

        __u64 *ingress_ts = bpf_map_lookup_elem(&ingress_ts_map, &pkt_key);
        if (ingress_ts) {
            inc_debug_counter(SOJOURN_DBG_INGRESS_TS_HIT);
            if (ts > *ingress_ts) {
                __u64 sojourn_ns = ts - *ingress_ts;
                struct sojourn_sample sample = {
                    .ingress_ts_ns = *ingress_ts,
                    .egress_ts_ns = ts,
                    .sojourn_ns = sojourn_ns,
                };

                bpf_map_update_elem(&sojourn_sample_map, &pkt_key, &sample, BPF_ANY);
                inc_debug_counter(SOJOURN_DBG_SAMPLE_UPDATE);

#if SOJOURN_DELETE_INGRESS_TS_AFTER_MATCH
                bpf_map_delete_elem(&ingress_ts_map, &pkt_key);
#endif
            }
        } else {
            inc_debug_counter(SOJOURN_DBG_INGRESS_TS_MISS);
        }
    }
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
