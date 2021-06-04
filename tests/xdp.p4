#include "xdp_model.p4"

struct ovs_packet {}

parser Parser(packet_in packet, out ovs_packet hdr) {
    state start {
        hdr = {};
        transition accept;
    }
}

control Ingress(inout ovs_packet hdr, in xdp_input xin, out xdp_output xout) {
    apply {
        xout.output_port = 0;
        xout.output_action = xdp_action.XDP_DROP;
    }
}

control Deparser(in ovs_packet hdrs, packet_out packet) {
    apply {
        ;
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
