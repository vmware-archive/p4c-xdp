#include "xdp_model.p4"

/* change ipv4.ttl to 4 */

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

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
    tcp_t   tcp;
    udp_t   udp;
    icmp_t icmp;
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
            8w6: parse_tcp;
            8w17: parse_udp;
            8w1: parse_icmp;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hd.icmp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hd.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hd.udp);
        transition accept;
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    bool xoutdrop = false;

    action Fallback_action()
    {
        hd.ipv4.ttl = 4;
        hd.ipv4.hdrChecksum = ebpf_ipv4_checksum(
                            hd.ipv4.version, hd.ipv4.ihl, hd.ipv4.diffserv,
                            hd.ipv4.totalLen, hd.ipv4.identification, hd.ipv4.flags,
                            hd.ipv4.fragOffset, hd.ipv4.ttl, hd.ipv4.protocol,
                            hd.ipv4.srcAddr, hd.ipv4.dstAddr);
        xoutdrop = false;
    }

    action Drop_action()
    {
        xoutdrop = true;
    }

    table dstmactable() {
        key = { hd.ethernet.protocol : exact; }
        actions = {
            Fallback_action;
            Drop_action;
        }
        default_action = Fallback_action;
        implementation = hash_table(64);
    }

    apply {
        dstmactable.apply();
        xout.output_port = 0;
        xout.output_action = xoutdrop ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
        packet.emit(hdrs.tcp);
    //    packet.emit(hdrs.udp);
        packet.emit(hdrs.icmp);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
