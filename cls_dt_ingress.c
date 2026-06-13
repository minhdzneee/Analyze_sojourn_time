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
#include "models/decision-tree/generated/decision_tree_rules.c"

// Target IP for Fast-Path Forwarding
static const __u32 target_ip = bpf_htonl(IP4(192, 168, 0, 162));
static const __u32 priority_dst_ip = bpf_htonl(IP4(192, 168, 3, 123));

#if INDIVIDUAL_PACKET_TRACING
/* struct bpf_elf_map SEC("maps") ingress_ts_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(struct pkt_id),
    .size_value = sizeof(__u64),
    .max_elem = 8192,
    .pinning = PIN_GLOBAL_NS, // pin so that it's visible to user-space app, 
                              // and persists independently of the programs using it
}; */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct pkt_id);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_ts_map SEC(".maps");

#endif

// eBPF Map to store the timestamp of the last processed packet
/* struct bpf_elf_map SEC("maps") last_ts_map_for_IAT = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(struct flow_id),
    .size_value = sizeof(struct flow_state),
    .max_elem = 8192,
    .pinning = 0,
}; */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_id);
    __type(value, struct flow_state);
} last_ts_map_for_IAT SEC(".maps");

SEC("classifier")
int classify_flow(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. Ethernet Header Check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only continue to process IPv4 packet, otherwise done (TC_ACT_OK)
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

    // 3. Layer 4 Header Check (TCP/UDP)
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);
        // Bounds check to ensure the TCP header is valid
        if ((void *)(tcp + 1) > data_end) {
            return TC_ACT_OK;
        }
        is_tcp = 1;
        src_port = bpf_ntohs(tcp->source);
        dest_port = bpf_ntohs(tcp->dest);
        tcp_seq = bpf_ntohl(tcp->seq); // Extract and convert to host byte order
        tcp_ack = bpf_ntohl(tcp->ack_seq);
        tcp_flags = ((__u8 *)tcp)[13]; // TCP flags are located at byte 13

#if INDIVIDUAL_PACKET_TRACING
        // Record Ingress Timestamp for Python Sojourn Calculation (TCP)
        struct pkt_id pkt_key = {};
        pkt_key.src_ip = iph->saddr;
        pkt_key.dst_ip = iph->daddr;
        pkt_key.src_port = src_port;
        pkt_key.dst_port = dest_port;
        pkt_key.protocol = IPPROTO_TCP;
        pkt_key.tcp_seq  = bpf_ntohl(tcp->seq);
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&ingress_ts_map, &pkt_key, &ts, BPF_ANY);
#endif

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        // Bounds check to ensure the UDP header is valid
        if ((void *)(udp + 1) > data_end) {
            return TC_ACT_OK;
        }
        src_port = bpf_ntohs(udp->source);
        dest_port = bpf_ntohs(udp->dest);
        __u16 ip_id = bpf_ntohs(iph->id); // Use IP ID for UDP packets
#if INDIVIDUAL_PACKET_TRACING
        // Record Ingress Timestamp for Python Sojourn Calculation (UDP)
        struct pkt_id pkt_key = {};
        pkt_key.src_ip = iph->saddr;
        pkt_key.dst_ip = iph->daddr;
        pkt_key.src_port = src_port;
        pkt_key.dst_port = dest_port;
        pkt_key.protocol = IPPROTO_UDP;
        pkt_key.ip_id    = bpf_ntohs(iph->id);         
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&ingress_ts_map, &pkt_key, &ts, BPF_ANY);
#endif       
    }

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
    // Example: Bypass if the Source IP is 192.168.0.10
    if (iph->saddr == target_ip) {
#if DEBUG_PRINT
        char fwd_fmt[] = "[INNN] Fast-forwarding intercepted IP: 0x%x\n";
        bpf_trace_printk(fwd_fmt, sizeof(fwd_fmt), bpf_ntohl(iph->saddr));
#endif
        // Swap Ethernet MAC addresses so the switch routes it back to the sender
        // (Required if bouncing the packet back out the same interface)
        unsigned char tmp_mac[6];
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }
        
        // Redirect packet directly to the egress hook (bypassing the host application)
        // hook point maybe here: https://elixir.bootlin.com/linux/v7.0.1/source/net/core/dev.c#L4786
        // before skb = sch_handle_egress(skb, &rc, dev); in net/core/dev.c
        return bpf_redirect(skb->ifindex, 0);
    }
#endif

    /* Decision Tree Logic */
//     struct flow_features features = {
//         .mean_fiat = mean_fiat_ns,
//         .max_fiat = max_fiat_ns
//     };

//     int is_realtime = predict_traffic_type(&features);

//     if (is_realtime == 1) {
//         // Prediction: realtime -> Assign tc class 1:7
//         struct __sk_buff *volatile skb_ptr = skb; // Avoid "pointer to stack memory" error
//         skb_ptr->priority = 0x10007;
// #if DEBUG_PRINT
//         char fmt[] = "[INNN] Realtime detected! Assigned class 1:7\n";
//         bpf_trace_printk(fmt, sizeof(fmt)); 
// #endif
//     } else {
//         // Prediction: non-realtime -> Assign tc class 1:1
//         struct __sk_buff *volatile skb_ptr = skb; // Avoid "pointer to stack memory" error
//         skb_ptr->priority = 0x10001;
// #if DEBUG_PRINT
//         char fmt[] = "[INNN] Non-realtime. Assigned class 1:1\n";
//         bpf_trace_printk(fmt, sizeof(fmt)); 
// #endif
//     }
    if (iph->daddr == priority_dst_ip) {
        // Assign high priority class for packets
        struct __sk_buff *volatile skb_ptr = skb; // Avoid "pointer to stack memory" error
        skb_ptr->priority = 0x10001; // Class 1:7 (high priority)
#if DEBUG_PRINT
        char fmt[] = "[INNN] Priority destination detected! Assigned class 1:7\n";
        bpf_trace_printk(fmt, sizeof(fmt)); 
#endif
    } else {
        struct __sk_buff *volatile skb_ptr = skb; // Avoid "pointer to stack memory" error
        skb_ptr->priority = 0x10003; // Class 1:1 (default priority)
#if DEBUG_PRINT
        char fmt[] = "[INNN] Regular destination. Assigned class 1:1\n";
        bpf_trace_printk(fmt, sizeof(fmt)); 
#endif
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
