#ifndef __CLS_DT_H
#define __CLS_DT_H

// Set to 0 to disable printk statements for high-performance production builds
#define DEBUG_PRINT 0

// Set to 1 to enable per-packet Sojourn time tracking, 0 to disable for performance
#define INDIVIDUAL_PACKET_TRACING 1

// Timestamp maps need enough room to hold packets until user-space can dump
// both ingress and egress maps. Start conservatively on RP4; raise to 131072
// later if map eviction is still visible and the program still loads.
#define SOJOURN_TS_MAP_MAX_ENTRIES 65536
#define SOJOURN_FLOW_MAP_MAX_ENTRIES 8192

// Keep egress_ts_map updates for the old Python packet matcher. The current
// monitor reads sojourn_sample_map, so this can stay off.
#define SOJOURN_STORE_EGRESS_TS 0
#define SOJOURN_DELETE_INGRESS_TS_AFTER_MATCH 1

/* iproute2 map pinning attributes */
enum {
    PIN_NONE = 0,       // Map is not pinned (ephemeral)
    PIN_OBJECT_NS = 1,  // Pinned to /sys/fs/bpf/tc/<object-file>/
    PIN_GLOBAL_NS = 2,  // Pinned to /sys/fs/bpf/tc/globals/
    PIN_CUSTOM_NS = 3,  // Pinned to a custom path defined in the ELF
};

// Helper macro to easily write IPv4 addresses (e.g., IP4(192, 168, 0, 10))
#define IP4(a, b, c, d) (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

// UDP packets do not have a stable 32-bit packet id. The ingress program
// writes this tagged per-flow sequence into skb->mark, and egress reads it
// back to match the same packet without relying on the 16-bit IPv4 IP_ID.
#define SOJOURN_MARK_MAGIC 0xA0000000u
#define SOJOURN_MARK_MASK  0xF0000000u
#define SOJOURN_SEQ_MASK   0x0FFFFFFFu
#define SOJOURN_CPU_SHIFT  24
#define SOJOURN_CPU_MASK   0x0F000000u
#define SOJOURN_CPU_ID_MASK 0x0Fu
#define SOJOURN_SEQ_COUNTER_MASK 0x00FFFFFFu

// Lightweight egress debug counters. These are map counters, not trace_printk,
// so they are safe to keep enabled while diagnosing packet matching.
#define SOJOURN_DBG_EGRESS_IPV4       0
#define SOJOURN_DBG_EGRESS_UDP        1
#define SOJOURN_DBG_UDP_MARK_OK       2
#define SOJOURN_DBG_UDP_MARK_BAD      3
#define SOJOURN_DBG_RECORD_PACKET     4
#define SOJOURN_DBG_INGRESS_TS_HIT    5
#define SOJOURN_DBG_INGRESS_TS_MISS   6
#define SOJOURN_DBG_SAMPLE_UPDATE     7
#define SOJOURN_DBG_COUNTERS          8

#if INDIVIDUAL_PACKET_TRACING

struct pkt_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;      // 6 for TCP, 17 for UDP
    __u8 _pad[3];       // Padding to align to 8 bytes
    union {
        __u32 tcp_seq;  // For TCP packets, use the sequence number as part of the key
        __u32 udp_seq;  // For UDP packets, use the ingress-generated sequence
    };
};

#endif

struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/*
 * Per-flow counter key for In/Eg/Drop statistics.
 * The protocol field is included so TCP and UDP flows with the same
 * src/dst IP and ports do not collide.
 */
struct flow_count_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;      // 6 for TCP, 17 for UDP
    __u8 _pad[3];       // Align key size to 16 bytes
};

/*
 * Per-packet sample produced at egress after the kernel has already matched
 * the packet with its ingress timestamp. User-space can print this in the old
 * sojourn_monitor.py log format without matching two timestamp maps itself.
 */
struct sojourn_sample {
    __u64 ingress_ts_ns;
    __u64 egress_ts_ns;
    __u64 sojourn_ns;
};

struct flow_state {
    __u64 last_ts;
    __u64 sum_iat_ns;
    __u64 max_iat_ns;
    __u32 packet_count;
};

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#endif /* __CLS_DT_H */
