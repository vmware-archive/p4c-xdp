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
    bit<16> checksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> checksum;
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
    // from, to are host byte order
    bit<16> from;
    bit<16> to;
    bit<32> from_addr;
    bit<32> to_addr;

    action Fallback_action()
    {
#if 0
        // UDP port
        from = hd.udp.dstPort;
        to = 16w0x400;
        hd.udp.dstPort = to;
        hd.udp.checksum = csum_replace2(hd.udp.checksum, from, to);

        // UDP IP addr
        from_addr = hd.ipv4.dstAddr;
        to_addr = 32w0x01020304;
        hd.ipv4.dstAddr = to_addr;
        hd.ipv4.checksum = csum_replace4(hd.ipv4.checksum, from_addr, to_addr);
        hd.udp.checksum = csum_replace4(hd.udp.checksum, from_addr, to_addr);
#endif
        // TCP
        from = hd.tcp.srcPort;
        to = 16w0x841;
        hd.tcp.srcPort = to;
        hd.tcp.checksum = csum_replace2(hd.tcp.checksum, from, to);

        // TCP IP addr
        from_addr = hd.ipv4.srcAddr;
        to_addr = 32w0x05060708;
        hd.ipv4.srcAddr = to_addr;
        hd.ipv4.checksum = csum_replace4(hd.ipv4.checksum, from_addr, to_addr);
        hd.tcp.checksum = csum_replace4(hd.tcp.checksum, from_addr, to_addr);

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

    // hit Verifier MAX_BPF_STACK issue
    //    packet.emit(hdrs.tcp);
    //    packet.emit(hdrs.udp);

        packet.emit(hdrs.icmp);
        packet.emit(hdrs.udp);
        packet.emit(hdrs.tcp);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
