/*
Copyright 2017 VMWare, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
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
        transition accept;
    }
}

control Ingress(inout Headers hdr, in xdp_input xin, out xdp_output xout) {
    apply {
        xout.output_port = 0;
        xout.output_action = (hdr.ethernet.protocol != 0x800) ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        ;
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
