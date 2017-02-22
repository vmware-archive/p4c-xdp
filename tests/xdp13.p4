#include "xdp_model.p4"

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

    xdp_action xact = xdp_action.XDP_PASS;

    action l2_Fallback_action() { xact = xdp_action.XDP_PASS; }
    action l2_Drop_action() { xact = xdp_action.XDP_DROP; }

    table l2table() {
        key = { hd.ethernet.protocol : exact; }
        actions = {
            l2_Fallback_action;
            l2_Drop_action;
        }
        default_action = l2_Fallback_action;
        implementation = hash_table(64);
    }

    action l3_Fallback_action() { xact = xdp_action.XDP_PASS; }
    action l3_Drop_action() { xact = xdp_action.XDP_DROP; }
    table l3table() {
        key = { hd.ipv4.dstAddr : exact; }
        actions = {
            l3_Fallback_action;
            l3_Drop_action;
        }
        default_action = l3_Fallback_action; 
        implementation = hash_table(64);
    }

    action l4_Fallback_action() { xact = xdp_action.XDP_PASS; }
    action l4_Drop_action() { xact = xdp_action.XDP_DROP; }
    table l4table() {
        key = {hd.icmp.typeCode : exact; }
        actions = {
            l4_Fallback_action;
            l4_Drop_action;
        }
        default_action = l4_Fallback_action;
        implementation = hash_table(64);
    }

    apply {
        l2table.apply();
        l3table.apply();
        l4table.apply();
        xout.output_port = 0;
        xout.output_action = xact;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        ;
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
