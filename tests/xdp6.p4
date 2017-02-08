#include "xdp_model.p4"

header Ethernet {
    bit<48> source;
    bit<48> destination;
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

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
}

struct action_md_t {
    bit<8> ttl;
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
        transition accept;
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    action SetTTL_action(action_md_t md)
    {
        hd.ipv4.ttl = md.ttl;
    }

    action Fallback_action()
    {
        xout.drop = false;
    }

    action Drop_action()
    {
        xout.drop = true;
    }

    table dstmactable() {
        key = { hd.ethernet.protocol : exact; }
        actions = {
            Fallback_action;
            Drop_action;
            SetTTL_action;
        }
        default_action = Drop_action; 
        implementation = hash_table(64);
    }

    apply {
        dstmactable.apply();
        xout.output_port = 0;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
