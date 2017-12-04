#include "xdp_model.p4"

const bit<8>  TCP_PROTOCOL   = 0x06;
const bit<8>  UDP_PROTOCOL   = 0x11;

typedef bit<48> macAddr_t;
typedef bit<32> ipAddr_t;

header eth_t {
    bit<48> destination;
    bit<48> source;
    bit<16> ethertype;
}

header vlan_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    //bit<16> ethertype;
}

header vxlan_t {
    bit<32> pre_reserved;
    bit<24> vni;
    bit<8> post_reserve;
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
    bit<16> hdChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t { 
    bit<16> srcPort; 
    bit<16> dstPort; 
    bit<32> seqNo; 
    bit<32> ackNo; 
    bit<4>  dataOffset; 
    bit<3>  res; 
    bit<3>  ecn; 
    bit<6>  ctrl; 
    bit<16> window; 
    bit<16> checksum; 
    bit<16> urgentPtr; 
} 
 
header udp_t { 
    bit<16> srcPort; 
    bit<16> dstPort;
    //bit<16> udpLen;
    //bit<16> udpChecksum; 
} 

struct Headers {
    eth_t 	eth;
    ipv4_t  	ipv4;
    tcp_t   	tcp;
    udp_t   	udp;
    vlan_t  	vlan;
    vxlan_t 	vxlan;
    eth_t 	outer_eth;
    ipv4_t 	outer_ipv4;
    udp_t 	outer_udp;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.eth);
        transition select(hd.eth.ethertype) {
            0x0800: parse_ipv4;
	    0x8100: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hd.vlan);
	transition accept;
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        transition select(hd.ipv4.protocol) {

// Verifer failed when enabled
//            TCP_PROTOCOL : parse_tcp;
//            UDP_PROTOCOL : parse_udp; 
	    default: accept;
	}
    }
/*
    state parse_tcp {
	packet.extract(hd.tcp);
	transition accept;
    }

    state parse_udp {
	packet.extract(hd.udp);
	transition accept;
    }
*/
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    action l2l3_lookup(macAddr_t dmac, macAddr_t smac, ipAddr_t dip, ipAddr_t sip) { 
	hd.outer_eth.destination = dmac;
        hd.outer_eth.source = smac;
        hd.outer_eth.setValid();

        hd.outer_ipv4.dstAddr = dip;
        hd.outer_ipv4.srcAddr = sip;
        hd.outer_ipv4.setValid();

    } 

    action l2_lookup(macAddr_t dmac, macAddr_t smac) {
    	hd.outer_eth.destination = dmac;
        hd.outer_eth.source = smac;
	hd.outer_eth.setValid();

    }

    action l3_lookup(ipAddr_t dip, ipAddr_t sip) {
	hd.outer_ipv4.dstAddr = dip;
        hd.outer_ipv4.srcAddr = sip;
        hd.outer_ipv4.setValid();
    }
 
    table l2l3_lookups { 
        key = { 
           //standard_metadata.ingress_port : exact;  
	   hd.ipv4.srcAddr : exact;
        }
 
        actions = { 
            l2l3_lookup;
	    l2_lookup;
	    l3_lookup;
        } 
	
	default_action = l2l3_lookup(0xAABBCCDDEEFF,0xFFEEDDCCBBAA,0xAAAAAAAA,0xBBBBBBBB);
	//default_action = l3_lookup(0xAAAAAAAA,0xBBBBBBBB);
	implementation = hash_table(64);

        const entries = { 
            (0) : l2l3_lookup(0xAABBCCDDEEFF,0xFFEEDDCCBBAA,0xa0000001,0x0a000001);
	    (0) : l2_lookup(0xAABBCCDDEEFF,0xFFEEDDCCBBAA);
 	    (0) : l3_lookup(0xa0000001,0x0a000001);
        }  

    } 

    apply {
	l2l3_lookups.apply();

        xout.output_port = 0;
        xout.output_action = xdp_action.XDP_TX;

	hd.outer_udp.srcPort = 0xbaaa;
	hd.outer_udp.dstPort = 4789;
        hd.outer_udp.setValid();
        
	hd.vxlan.pre_reserved = 0xcafebeef;
	hd.vxlan.vni = 0xFFFFFF;
	hd.vxlan.post_reserve = 0xbe;
        hd.vxlan.setValid();

        hd.outer_ipv4.dstAddr = 0xFFFFFFFF;
        hd.outer_ipv4.srcAddr = 0xCCCCCCCC;
	hd.outer_ipv4.setValid();	

	hd.outer_eth.destination = 0x112233445566;
	hd.outer_eth.source = 0x223344556677;

// Verifier failed
//	hd.outer_eth.setValid();
    }
}

control Deparser(in Headers hds, packet_out packet) {
    apply {
        packet.emit(hds.outer_eth);
	packet.emit(hds.vlan);
	packet.emit(hds.outer_ipv4);
	packet.emit(hds.outer_udp);
	packet.emit(hds.vxlan);
        packet.emit(hds.eth);
        packet.emit(hds.ipv4);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;

