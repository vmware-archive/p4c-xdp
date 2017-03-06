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

/* encap my own header */
header myhdr_t {
    bit<32> id;
    bit<32> timestamp;
}

struct Headers {
    Ethernet ethernet;
    myhdr_t  myhdr;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            default: accept;
        }
    }
}

control Ingress(inout Headers hdr, in xdp_input xin, out xdp_output xout) {

    apply {
        hdr.myhdr.id = 0xfefefefe; // get ID from map or else
        hdr.myhdr.timestamp = 0x12345678;
        hdr.myhdr.setValid();
        xout.output_port = 0;
        xout.output_action = xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.myhdr);
        packet.emit(hdrs.ethernet);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
