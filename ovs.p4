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
    flow_tnl_t     tnl_md;
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

    // parse ovs skb metadata
    // p.skb_mark = @skb("mark"); 
    // p.skb_priority = @skb("priority");
    // more...
}

control InPipe(inout ovs_packet headers,
               //in input_metadata md,
               out bool pass)
               /*
               in error parseError,
               out McastControl ports // list of output ports)
               */
{
    /* 'bitmap' shows which action should be executed, 
       'md' is the corresponding action's metadata.

    action ovs_dp_actions(bitmap, md[]) {
        if (bitmap & DROP_MASK)
            tc_drop.exec();
        
        if (bitmap & OUTPUT_MASK)
            clone_redirect.exec(md[i++].port);
            // or should we use redirect.exec()?

        if (bitmap & TRUNC_MASK) // truncate the packet
            change_tail.exec(md[i++].new_len, flags); 

        if (bitmap & HASH_MASK)
            get_hash.exec();

        if (bitmap & PUSH_VLAN_MASK)
            push_vlan.exec(md[i++].vid);

        if (bitmap & POP_VLAN_MASK)
            pop_vlan.exec();

        if (bitmap & UPCALL_MASK)
            // Send to CPU, ovs-vswitchd userspace for
            // resolving the flow actions
            perf_event_output.exec(packet_in p, in skb);

        if (bitmap & SET_TUNNEL_MASK)
            // light weight tunneling protocol support
            set_tunnel_key.exec();

        if (bitmap & GET_TUNNEL_MASK)
            get_tunnel_key.exec();

        // more actions later
    }
    */
    /**
     * Use headers as key to lookup OVS actions list
     * @parm headers
     * @parm action_bitmap the executing actions
     * @parm action_md_list executing actions' metadata
    
    table ovs_match_action(in ovs_packet headers, out McastCtrl mcast) {
        key = {headers : exact; };
        
        /* use bitmap here?
        actions = {
            tc_bypass; // fallback to linux
            ovs_dp_actions(in OvsActBitmap action_bitmap,
                           in OvsActMd action_md,   // action metadata
                           out McastCtrl mcast);    // read by mcast engine

            // how do we specify mcast engine?
        }

        size = 1024;
        default_action = tc_bypass;
    }
    */
    
    apply {
        //ovs_match_action.apply(headers, mcast_ctrl);
        // we can choose to use mcast engine or not
        pass = false;
    }

}

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

ebpfFilter(TopParser(), InPipe()) main;
