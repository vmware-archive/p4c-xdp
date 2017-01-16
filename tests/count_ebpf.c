#define KBUILD_MODNAME "xdptest"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

static __always_inline int ebpf_filter(struct xdp_md *skb);

#define load_byte(data, b)  (*(u8 *)(data + (b)))
#define load_half(data, b) __constant_ntohs(*(u16 *)(data + (b)))
#define load_word(data, b) __constant_ntohl(*(u32 *)(data + (b)))
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

struct Ethernet_h {
    char dstAddr[6]; /* EthernetAddress */
    char srcAddr[6]; /* EthernetAddress */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};

struct IPv4_h {
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
    u32 srcAddr; /* IPv4Address */
    u32 dstAddr; /* IPv4Address */
    u8 ebpf_valid;
};

struct Headers_t {
    struct Ethernet_h ethernet; /* Ethernet_h */
    struct IPv4_h ipv4; /* IPv4_h */
};

struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), 
    .value_size = sizeof(u32), 
    .max_entries = 10, 
};

SEC("prog")
int ebpf_filter(struct xdp_md* skb){
    struct Headers_t headers = {
        .ethernet = {
            .ebpf_valid = 0
        },
        .ipv4 = {
            .ebpf_valid = 0
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;
    enum ebpf_errorCodes ebpf_errorCode = NoError;
    void* ebpf_packetStart = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u8 pass = 0;
    u32 ebpf_zero = 0;

    goto start;
    start: {
        /* extract(headers.ethernet)*/
        if (ebpf_packetEnd < ebpf_packetStart + BYTES(ebpf_packetOffsetInBits + 112)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        headers.ethernet.dstAddr[0] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        headers.ethernet.dstAddr[1] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        headers.ethernet.dstAddr[2] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        headers.ethernet.dstAddr[3] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        headers.ethernet.dstAddr[4] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        headers.ethernet.dstAddr[5] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;

        headers.ethernet.srcAddr[0] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 0) >> 0));
        headers.ethernet.srcAddr[1] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 1) >> 0));
        headers.ethernet.srcAddr[2] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 2) >> 0));
        headers.ethernet.srcAddr[3] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 3) >> 0));
        headers.ethernet.srcAddr[4] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 4) >> 0));
        headers.ethernet.srcAddr[5] = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;

        headers.ethernet.etherType = (u16)((load_half(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers.ethernet.ebpf_valid = 1;

        switch (headers.ethernet.etherType) {
            case 2048: goto ip;
            default: goto reject;
        }
    }
    ip: {
        /* extract(headers.ipv4)*/
        if (ebpf_packetEnd < ebpf_packetStart + BYTES(ebpf_packetOffsetInBits + 160)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }
        headers.ipv4.version = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        headers.ipv4.ihl = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        headers.ipv4.diffserv = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers.ipv4.totalLen = (u16)((load_half(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers.ipv4.identification = (u16)((load_half(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers.ipv4.flags = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers.ipv4.fragOffset = (u16)((load_half(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
        ebpf_packetOffsetInBits += 13;

        headers.ipv4.ttl = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers.ipv4.protocol = (u8)((load_byte(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers.ipv4.hdrChecksum = (u16)((load_half(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers.ipv4.srcAddr = (u32)((load_word(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers.ipv4.dstAddr = (u32)((load_word(((void*)(long)skb->data), BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers.ipv4.ebpf_valid = 1;

        goto accept;
    }

    reject: { return 1; }

    accept:
    {
        u8 hit;
        {
            if (headers.ipv4.ebpf_valid) {
                {
                    u32 *value;
                    u32 init_val = 1;
                    u32 key_0 = ((u32)headers.ipv4.dstAddr);
                    value = bpf_map_lookup_elem(&counters, &key_0);
                    if (value != NULL)
                        __sync_fetch_and_add(value, 1);
                    else
                        bpf_map_update_elem(&counters, &key_0, &init_val, BPF_ANY);
                }
;
                pass = true;
            }
            else 
                pass = false;
        }
    }
    ebpf_end:
    return pass;
}
char _license[] SEC("license") = "GPL";
