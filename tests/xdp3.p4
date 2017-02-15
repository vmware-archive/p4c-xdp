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

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdrChecksum;
}

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
    icmp_h     icmp;
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
		8w0x1: parse_icmp;
		default: accept;
	}
    }

    state parse_icmp {
	packet.extract(hd.icmp);
	transition accept;
    }
}

control Ingress(inout Headers hdr, in xdp_input xin, out xdp_output xout) {
    apply {
        xout.output_port = 0;
        xout.output_action = hdr.ethernet.protocol != 0x800 ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
	packet.emit(hdrs.icmp);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
