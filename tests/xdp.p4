#include "xdp_model.p4"

struct ovs_packet {}

parser Parser(packet_in packet, out ovs_packet hdr) {
    state start {
        transition accept;
    }
}

control Ingress(inout ovs_packet hdr, in xdp_input xin, out xdp_output xout) {
    apply {}
}

control Deparser(in ovs_packet hdr, packet_out packet) {
    apply {}
}

xdp(Parser(), Ingress(), Deparser()) main;
