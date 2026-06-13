#ifndef __CLS_DT_H
#define __CLS_DT_H

// Set to 0 to disable printk statements for high-performance production builds
#define DEBUG_PRINT 1

// Set to 1 to enable per-packet Sojourn time tracking, 0 to disable for performance
#define INDIVIDUAL_PACKET_TRACING 1

/* iproute2 map pinning attributes */
enum {
    PIN_NONE = 0,      // Map is not pinned (ephemeral)
    PIN_OBJECT_NS = 1, // Pinned to /sys/fs/bpf/tc/<object-file>/
    PIN_GLOBAL_NS = 2, // Pinned to /sys/fs/bpf/tc/globals/
    PIN_CUSTOM_NS = 3, // Pinned to a custom path defined in the ELF
};

// Helper macro to easily write IPv4 addresses (e.g., IP4(192, 168, 0, 10))
#define IP4(a, b, c, d) (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

#if INDIVIDUAL_PACKET_TRACING
struct pkt_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol; // 6 for TCP, 17 for UDP
    __u8 _pad[3]; // Padding to align to 8 bytes
 union {
        __u32 tcp_seq; // For TCP packets, use the sequence number as part of the key
        __u16 ip_id;   // For UDP packets, use the IP ID as part of the key
    };
};
#endif

struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
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