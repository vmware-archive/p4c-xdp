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

header IPv6 {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
    IPv6     ipv6;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            16w0x0800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        transition accept;
    }
    state parse_ipv6 {
        packet.extract(hd.ipv6);
        transition accept;
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    bool xoutdrop = false;
    CounterArray(32w10, true) counters;

    apply {
        if (hd.ipv4.isValid())
        {
            counters.increment((bit<32>)hd.ipv4.dstAddr);
            xoutdrop = false;
        }
        if (hd.ipv6.isValid())
        {
            xoutdrop = true;
        }
        xout.output_port = 0;
        xout.output_action = xoutdrop ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
        packet.emit(hdrs.ipv6);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
