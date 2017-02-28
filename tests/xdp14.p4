#include "xdp_model.p4"

#define OUTPUT_OFS      (1<<0)
#define PUSHVLAN_OFS    (1<<1)
#define SETTUNNEL_OFS   (1<<2)

header Ethernet {
    bit<48> destination;
    bit<48> source;
    bit<16> protocol;
}

header IPv4 {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
    icmp_t   icmp;
}

struct output_md_t {
    bit<32> port;   /* ifindex */
}

struct pushvlan_md_t {
    bit<16> tci;
    bit<16> proto;
}

struct settunnel_md_t {
    bit<32> ip_dst; 
    bit<32> ip_src;
    bit<64> tun_id;
    bit<16> flags;
}

struct action_md_t {
    output_md_t output;
    pushvlan_md_t pushvlan;
    settunnel_md_t settunnel;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hd.ipv4);
        transition select(hd.ipv4.protocol) {
            8w1: parse_icmp;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hd.icmp);
        transition accept;
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    bit<32> outport = 0;
    bit<32> bitmap = 0;
    action_md_t action_md;
    xdp_action xact = xdp_action.XDP_PASS;

    action output() {
        outport = action_md.output.port;
        xact = xdp_action.XDP_DROP;
    }
    action push_vlan() {
        bit<16> tci = action_md.pushvlan.tci;
        bit<16> proto = action_md.pushvlan.proto;
        // bpf_skb_vlan_push not support in XDP
        // how to inform deparser?
    }
    action set_tunnel() {
        bit<32> dst = action_md.settunnel.ip_dst;
        bit<32> src = action_md.settunnel.ip_src;
        bit<64> tun_id = action_md.settunnel.tun_id;
        bit<16> flags = action_md.settunnel.flags;
        // bpf_skb_set_tunnel_key not support in XDP
        // how to pass tunnel key to deparser?
    }
    action fallback() {
        xact = xdp_action.XDP_PASS;
    }

    action exec_action(bit<32> __bitmap, action_md_t md) {
        bitmap = __bitmap;
        action_md = md;
    }

    table action_bitmap() {
        key = { hd.ethernet.protocol : exact; }
        actions = {
            fallback;
            exec_action;
        }
        default_action = fallback;
        implementation = hash_table(64);
    }

    apply {
        //action_md.output.port = 0;
        action_bitmap.apply();

        /* Execute 3 actions in order, if its bit is set */
        if ((bitmap & PUSHVLAN_OFS) != 0) {
            push_vlan();
        }
        if ((bitmap & SETTUNNEL_OFS) != 0) {
            set_tunnel();
        }
        if ((bitmap & OUTPUT_OFS) != 0) {
            output();
        }
        xout.output_port = outport;
        xout.output_action = xact;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        ; // We do not change packet content
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
