#include "xdp_model.p4"

header some {
    bit<32> b;
}

struct ovs_packet {
    some some;
}

parser Parser(packet_in packet, out ovs_packet hdr) {
    state start {
        hdr = { { 0 } };
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
        if (hdrs.some.isValid() && hdrs.some.b != 0)
           packet.emit(hdrs.some);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
