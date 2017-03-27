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

// your customized header
header myhdr_t {
    bit<32> id;
    bit<32> ts; // timestamp
}

struct Headers {
    myhdr_t myhdr;
    Ethernet ethernet;
}

parser Parser(packet_in packet, out Headers hd) {
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            default: accept;
        }
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    bool xoutdrop = false;
    action TS_action()
    {
        // Get the timestamp by calling BPF helper
        hd.myhdr.ts = BPF_KTIME_GET_NS();
        hd.myhdr.id = 0xfefefefe;
        xoutdrop = false;
    }

    action Drop_action()
    {
        // Send the packet to userspace before drop
        BPF_PERF_EVENT_OUTPUT();
        xoutdrop = true;
    }

    table dstmactable {
        key = { hd.ethernet.protocol : exact; }
        actions = {
            TS_action;
            Drop_action;
        }
        default_action = TS_action;
        implementation = hash_table(64);
    }

    apply {
        dstmactable.apply();
        // set valid of myhdr so deparser will emit
        hd.myhdr.setValid();
        xout.output_port = 0;
        xout.output_action = xoutdrop ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        // prepend the customized header in the front
        packet.emit(hdrs.myhdr);
        packet.emit(hdrs.ethernet);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
