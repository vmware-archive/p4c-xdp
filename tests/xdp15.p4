#include "xdp_model.p4"

header Ethernet {
    bit<48> destination;
    bit<48> source;
    bit<16> protocol;
}

/* encap my own header */
header myhdr_t {
    bit<32> id;
    bit<32> timestamp;
}

struct Headers {
    Ethernet ethernet;
    myhdr_t  myhdr;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            default: accept;
        }
    }
}

control Ingress(inout Headers hdr, in xdp_input xin, out xdp_output xout) {

    apply {
        hdr.myhdr.id = 0xfefefefe; // get ID from map or else
        hdr.myhdr.timestamp = 0x12345678;
        hdr.myhdr.setValid();
        xout.output_port = 0;
        xout.output_action = xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.myhdr);
        packet.emit(hdrs.ethernet);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
