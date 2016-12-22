#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
/* TODO: these should be in some header somewhere in the kernel, but where? */
#define SEC(NAME) __attribute__((section(NAME), used))
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
        (void *) BPF_FUNC_map_lookup_elem;
unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");
struct bpf_map_def {
        __u32 type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 flags;
        __u32 id;
        __u32 pinning;
};
SEC("_ebpf_filter") int ebpf_filter(struct __sk_buff *skb);

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
                              (void *) BPF_FUNC_trace_printk;
#define printk(fmt, ...)    \
({  char ___fmt[] = fmt;    \
    bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
})
enum ebpf_errorCodes {
    NoError,
    PacketTooShort,
    NoMatch,
    EmptyStack,
    FullStack,
    OverwritingHeader,
    HeaderTooShort,
    ParserTimeout,
};

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w + 7) / 8)

struct pkt_metadata_t {
    u32 recirc_id; /* bit<32> */
    u32 dp_hash; /* bit<32> */
    u32 skb_priority; /* bit<32> */
    u32 pkt_mark; /* bit<32> */
    u16 ct_state; /* bit<16> */
    u16 ct_zone; /* bit<16> */
    u32 ct_mark; /* bit<32> */
    char ct_label[16]; /* bit<128> */
    u32 in_port; /* bit<32> */
};

struct flow_tnl_t {
    u32 ip_dst; /* bit<32> */
    char ipv6_dst[8]; /* bit<64> */
    u32 ip_src; /* bit<32> */
    char ipv6_src[8]; /* bit<64> */
    char tun_id[8]; /* bit<64> */
    u16 flags; /* bit<16> */
    u8 ip_tos; /* bit<8> */
    u8 ip_ttl; /* bit<8> */
    u16 tp_src; /* bit<16> */
    u16 tp_dst; /* bit<16> */
    u16 gbp_id; /* bit<16> */
    u8 gbp_flags; /* bit<8> */
    char pad1[5]; /* bit<40> */
};

struct arp_rarp_t {
    u16 hwType; /* bit<16> */
    u16 protoType; /* bit<16> */
    u8 hwAddrLen; /* bit<8> */
    u8 protoAddrLen; /* bit<8> */
    u16 opcode; /* bit<16> */
    u8 ebpf_valid;
};

struct ethernet_t {
    char dstAddr[6]; /* bit<48> */
    char srcAddr[6]; /* bit<48> */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};

struct icmp_t {
    u16 typeCode; /* bit<16> */
    u16 hdrChecksum; /* bit<16> */
    u8 ebpf_valid;
};

struct ipv4_t {
    u8 version; /* bit<4> */
    u8 ihl; /* bit<4> */
    u8 diffserv; /* bit<8> */
    u16 totalLen; /* bit<16> */
    u16 identification; /* bit<16> */
    u8 flags; /* bit<3> */
    u16 fragOffset; /* bit<13> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdrChecksum; /* bit<16> */
    u32 srcAddr; /* bit<32> */
    u32 dstAddr; /* bit<32> */
    u8 ebpf_valid;
};

struct ipv6_t {
    u8 version; /* bit<4> */
    u8 trafficClass; /* bit<8> */
    u32 flowLabel; /* bit<20> */
    u16 payloadLen; /* bit<16> */
    u8 nextHdr; /* bit<8> */
    u8 hopLimit; /* bit<8> */
    char srcAddr[16]; /* bit<128> */
    char dstAddr[16]; /* bit<128> */
    u8 ebpf_valid;
};

struct tcp_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u32 seqNo; /* bit<32> */
    u32 ackNo; /* bit<32> */
    u8 dataOffset; /* bit<4> */
    u8 res; /* bit<4> */
    u8 flags; /* bit<8> */
    u16 window; /* bit<16> */
    u16 checksum; /* bit<16> */
    u16 urgentPtr; /* bit<16> */
    u8 ebpf_valid;
};

struct udp_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u16 length_; /* bit<16> */
    u16 checksum; /* bit<16> */
    u8 ebpf_valid;
};

struct vlan_tag_t {
    u8 pcp; /* bit<3> */
    u8 cfi; /* bit<1> */
    u16 vid; /* bit<12> */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};

struct metadata {
    struct pkt_metadata_t md; /* pkt_metadata_t */
    struct flow_tnl_t tnl; /* flow_tnl_t */
};

struct ovs_packet {
    struct arp_rarp_t arp; /* arp_rarp_t */
    struct ethernet_t ethernet; /* ethernet_t */
    struct icmp_t icmp; /* icmp_t */
    struct ipv4_t ipv4; /* ipv4_t */
    struct ipv6_t ipv6; /* ipv6_t */
    struct tcp_t tcp; /* tcp_t */
    struct udp_t udp; /* udp_t */
    struct vlan_tag_t vlan; /* vlan_tag_t */
};

struct match_action_key {
    u32 field0;
};
enum match_action_actions {
    Output,
    SetTunnelKey,
    PushVlan,
    PopVlan,
    Reject,
    NoAction_1,
};
struct match_action_value {
    enum match_action_actions action;
    union {
        struct {
            u32 port;
        } Output;
        struct {
            struct flow_tnl_t tnl;
        } SetTunnelKey;
        struct {
        } PushVlan;
        struct {
        } PopVlan;
        struct {
            u32 addr;
        } Reject;
        struct {
        } NoAction_1;
    } u;
};
struct bpf_map_def SEC("maps") match_action = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct match_action_key), 
    .value_size = sizeof(struct match_action_value), 
    .pinning = 2, //PIN_GLOBAL_NS
    .max_entries = 1024, 
};
struct bpf_map_def SEC("maps") match_action_defaultAction = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32), 
    .value_size = sizeof(struct match_action_value), 
    .pinning = 2, //PIN_GLOBAL_NS
    .max_entries = 1, 
};

int ebpf_filter(struct __sk_buff* skb) {
    struct ovs_packet hdr = {
        .arp = {
            .ebpf_valid = 0
        },
        .ethernet = {
            .ebpf_valid = 0
        },
        .icmp = {
            .ebpf_valid = 0
        },
        .ipv4 = {
            .ebpf_valid = 0
        },
        .ipv6 = {
            .ebpf_valid = 0
        },
        .tcp = {
            .ebpf_valid = 0
        },
        .udp = {
            .ebpf_valid = 0
        },
        .vlan = {
            .ebpf_valid = 0
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;
    enum ebpf_errorCodes ebpf_errorCode = NoError;
    u8 pass = 0;
    u32 ebpf_zero = 0;

    goto start;
    parse_arp: {
        /* extract(hdr.arp)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.arp.hwType = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.arp.protoType = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.arp.hwAddrLen = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.arp.protoAddrLen = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.arp.opcode = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.arp.ebpf_valid = 1;

        goto accept;
    }
    parse_icmp: {
        /* extract(hdr.icmp)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.icmp.typeCode = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.icmp.hdrChecksum = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.icmp.ebpf_valid = 1;

        goto accept;
    }
    parse_ipv4: {
        /* extract(hdr.ipv4)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.version = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.ihl = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.diffserv = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.totalLen = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.identification = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 3)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.flags = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 13)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.fragOffset = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
        ebpf_packetOffsetInBits += 13;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.ttl = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.protocol = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.hdrChecksum = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.srcAddr = (u32)((load_word(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv4.dstAddr = (u32)((load_word(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr.ipv4.ebpf_valid = 1;

        switch (hdr.ipv4.protocol) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 1: goto parse_icmp;
            default: goto accept;
        }
    }
    parse_ipv6: {
        /* extract(hdr.ipv6)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.version = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.trafficClass = (u8)((load_half(skb, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 8));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 20)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.flowLabel = (u32)((load_word(skb, BYTES(ebpf_packetOffsetInBits)) >> 8) & EBPF_MASK(u32, 20));
        ebpf_packetOffsetInBits += 20;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.payloadLen = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.nextHdr = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.hopLimit = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 128)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.srcAddr[0] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        hdr.ipv6.srcAddr[1] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        hdr.ipv6.srcAddr[2] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        hdr.ipv6.srcAddr[3] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        hdr.ipv6.srcAddr[4] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        hdr.ipv6.srcAddr[5] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        hdr.ipv6.srcAddr[6] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 6) >> 0));
        hdr.ipv6.srcAddr[7] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 7) >> 0));
        hdr.ipv6.srcAddr[8] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 8) >> 0));
        hdr.ipv6.srcAddr[9] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 9) >> 0));
        hdr.ipv6.srcAddr[10] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 10) >> 0));
        hdr.ipv6.srcAddr[11] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 11) >> 0));
        hdr.ipv6.srcAddr[12] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 12) >> 0));
        hdr.ipv6.srcAddr[13] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 13) >> 0));
        hdr.ipv6.srcAddr[14] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 14) >> 0));
        hdr.ipv6.srcAddr[15] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 15) >> 0));
        ebpf_packetOffsetInBits += 128;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 128)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ipv6.dstAddr[0] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        hdr.ipv6.dstAddr[1] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        hdr.ipv6.dstAddr[2] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        hdr.ipv6.dstAddr[3] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        hdr.ipv6.dstAddr[4] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        hdr.ipv6.dstAddr[5] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        hdr.ipv6.dstAddr[6] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 6) >> 0));
        hdr.ipv6.dstAddr[7] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 7) >> 0));
        hdr.ipv6.dstAddr[8] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 8) >> 0));
        hdr.ipv6.dstAddr[9] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 9) >> 0));
        hdr.ipv6.dstAddr[10] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 10) >> 0));
        hdr.ipv6.dstAddr[11] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 11) >> 0));
        hdr.ipv6.dstAddr[12] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 12) >> 0));
        hdr.ipv6.dstAddr[13] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 13) >> 0));
        hdr.ipv6.dstAddr[14] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 14) >> 0));
        hdr.ipv6.dstAddr[15] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 15) >> 0));
        ebpf_packetOffsetInBits += 128;

        hdr.ipv6.ebpf_valid = 1;

        switch (hdr.ipv6.nextHdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 1: goto parse_icmp;
            default: goto accept;
        }
    }
    parse_tcp: {
        /* extract(hdr.tcp)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.srcPort = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.dstPort = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.seqNo = (u32)((load_word(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.ackNo = (u32)((load_word(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.dataOffset = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.res = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.flags = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.window = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.checksum = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.tcp.urgentPtr = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.tcp.ebpf_valid = 1;

        goto accept;
    }
    parse_udp: {
        /* extract(hdr.udp)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.udp.srcPort = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.udp.dstPort = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.udp.length_ = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.udp.checksum = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.udp.ebpf_valid = 1;

        goto accept;
    }
    parse_vlan: {
        /* extract(hdr.vlan)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 3)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.vlan.pcp = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 1)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.vlan.cfi = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 12)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.vlan.vid = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 12));
        ebpf_packetOffsetInBits += 12;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.vlan.etherType = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.vlan.ebpf_valid = 1;

        switch (hdr.vlan.etherType) {
            case 2054: goto parse_arp;
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            default: goto accept;
        }
    }
    start: {
        /* extract(hdr.ethernet)*/
        if (skb->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ethernet.dstAddr[0] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        hdr.ethernet.dstAddr[1] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        hdr.ethernet.dstAddr[2] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        hdr.ethernet.dstAddr[3] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        hdr.ethernet.dstAddr[4] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        hdr.ethernet.dstAddr[5] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ethernet.srcAddr[0] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        hdr.ethernet.srcAddr[1] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        hdr.ethernet.srcAddr[2] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        hdr.ethernet.srcAddr[3] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        hdr.ethernet.srcAddr[4] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        hdr.ethernet.srcAddr[5] = (u8)((load_byte(skb, BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;

        if (skb->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        hdr.ethernet.etherType = (u16)((load_half(skb, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr.ethernet.ebpf_valid = 1;

        switch (hdr.ethernet.etherType) {
            case 33024: goto parse_vlan;
            case 34984: goto parse_vlan;
            case 2054: goto parse_arp;
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            default: goto accept;
        }
    }

    reject: { return 1; }

    accept:
    {
        u8 hit;
        struct metadata md_1;
        u32 outputPort;
        {
            pass = true;
            enum match_action_actions action_run;
            {
                /* construct key */
                struct match_action_key key;
                key.field0 = hdr.ipv4.srcAddr;
                /* value */
                struct match_action_value *value;
                /* perform lookup */
                value = bpf_map_lookup_elem(&match_action, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit = 0;
                    value = bpf_map_lookup_elem(&match_action_defaultAction, &ebpf_zero);
                } else {
                    hit = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case Output: 
                        {
                            outputPort = value->u.Output.port;
                        }
                        break;
                        case SetTunnelKey: 
                        {
                            md.tnl.ip_dst = value->u.SetTunnelKey.tnl.ip_dst;
                            md.tnl.ip_src = value->u.SetTunnelKey.tnl.ip_src;
                            md.tnl.ip_ttl = value->u.SetTunnelKey.tnl.ip_ttl;
                        }
                        break;
                        case PushVlan: 
                        {
                        }
                        break;
                        case PopVlan: 
                        {
                        }
                        break;
                        case Reject: 
                        {
                            pass = false;
                            hdr.ipv4.srcAddr = value->u.Reject.addr;
                        }
                        break;
                        case NoAction_1: 
                        {
                        }
                        break;
                    }
                    action_run = value->action;
                }
            }
            switch (action_run) {
                case Output:
                {
                }
                break;
                case SetTunnelKey:
                {
                }
                break;
                case PushVlan:
                {
                }
                break;
                case Reject:
                {
                    pass = false;
                }
                break;
                case NoAction_1:
                {
                }
                break;
            }
        }
    }
    ebpf_end:
    return pass;
}
char _license[] SEC("license") = "GPL";
