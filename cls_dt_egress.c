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
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct pkt_id);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} egress_ts_map SEC(".maps");
#endif

SEC("egress")
int check_egress_priority(struct __sk_buff *skb) {
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
    } 
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udp + 1) <= data_end) {
            pkt_key.src_ip = iph->saddr;
            pkt_key.dst_ip = iph->daddr;
            pkt_key.src_port = bpf_ntohs(udp->source);
            pkt_key.dst_port = bpf_ntohs(udp->dest);
			pkt_key.protocol = IPPROTO_UDP;
            pkt_key.ip_id = bpf_ntohs(iph->id); 
            record_packet = 1;
        }
    }

    if (record_packet) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&egress_ts_map, &pkt_key, &ts, BPF_ANY);
    }
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
