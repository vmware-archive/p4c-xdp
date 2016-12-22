/*
    OVS.p4 using tc-ebpf P4 architecture
Requirements:
- This should be an example which uses tc-ebpf P4 model to implement
  all the protocols supported by OVS.

Protocol supports:
    - L2: VLAN,...
    - L3: ...
Tunneling:
    - Support Linux's bpf tunnel protocol (ipip, vxlan, gre, geneve, etc)
*/

// TODO: define a new model ovs_ebpf_model.p4
#include <ebpf_model.p4>

struct pkt_metadata_t {
    bit<32>  recirc_id;
    bit<32>  dp_hash;
    bit<32>  skb_priority;
    bit<32>  pkt_mark;
    bit<16>  ct_state;
    bit<16>  ct_zone;
    bit<32>  ct_mark;
    bit<128> ct_label;
    bit<32>  in_port;
}

struct flow_tnl_t {
    bit<32> ip_dst;
    bit<64> ipv6_dst;
    bit<32> ip_src;
    bit<64> ipv6_src;
    bit<64> tun_id;
    bit<16> flags;
    bit<8>  ip_tos;
    bit<8>  ip_ttl;
    bit<16> tp_src;
    bit<16> tp_dst;
    bit<16> gbp_id;
    bit<8>  gbp_flags;
    bit<40> pad1;
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header ipv4_t {
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

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
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

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

struct metadata {
    pkt_metadata_t md;
    flow_tnl_t     tnl;
}

struct ovs_packet {
    arp_rarp_t arp;
    ethernet_t ethernet;
    icmp_t     icmp;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
    tcp_t      tcp;
    udp_t      udp;
    vlan_tag_t vlan;
}

/* implement OVS's key_extract() in net/openvswitch/flow.c */
parser TopParser(packet_in packet, /*inout bpf_sk_buff skbU, */ out ovs_packet hdr)
{
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x8100: parse_vlan;
            16w0x88a8: parse_vlan;
            16w0x806: parse_arp;
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            8w17: parse_udp;
            8w1: parse_icmp;
            default: accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w6: parse_tcp;
            8w17: parse_udp;
            8w1: parse_icmp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            16w0x806: parse_arp;
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    state start {
        transition parse_ethernet;
    }
}

control Ingress(inout ovs_packet hdr,
                out bool pass)
{
    // TODO: This should become an in parameter of Ingress
    metadata md;
    // TODO: this should become an out parameter of Ingress
    bit<32> outputPort;

    action Output(bit<32> port)
    {
        outputPort = port;
    }

    action SetTunnelKey(flow_tnl_t tnl)
    {
        md.tnl.ip_dst = tnl.ip_dst;
        md.tnl.ip_src = tnl.ip_src;
        md.tnl.ip_ttl = tnl.ip_ttl;
        // bpf_set_tunnel_key
    }

    action PushVlan()
    {
        //extern bpf_skb_push_vlan
    }

    action PopVlan()
    {
        //exten bpf_skb_pop_vlan
    }

    action Reject(bit<32> addr)
    {
        pass = false;
        hdr.ipv4.srcAddr = addr;
    }

    table match_action()
    {
        key = { hdr.ipv4.srcAddr : exact; }
        actions =
        {
            Output;
            SetTunnelKey;
            PushVlan;
            PopVlan;
            Reject;
            NoAction;
        }

        implementation = hash_table(1024);
        const default_action = NoAction;
    }

    apply {
        pass = true;

        switch (match_action.apply().action_run) {
        Output: {

        }
        SetTunnelKey: {

        }
        PushVlan: {

        }
        Reject: {
            pass = false;
        }
        NoAction: {}
        }
    }
}

// TODO: this should be argument to the new model ovs_ebpf_model()
control Deparser(packet_out packet, in ovs_packet hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.arp);
    }
}

// TODO: replace this with ovs_ebpf_model
ebpfFilter(TopParser(), Ingress()) main;
