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
        transition select(hd.ipv4.protocol) {
            default: accept;
        }
    }
}

control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {
    bool xoutdrop = false;
    CounterArray(32w10, true) counters;

    action SetTTL_action()
    {
        hd.ipv4.ttl = 4;
        xoutdrop = false;
    }

    action Fallback_action()
    {
        xoutdrop = false;
    }

    action Drop_action()
    {
        xoutdrop = true;
    }

    table dstmactable {
        key = { hd.ipv4.dstAddr : exact; }
        actions = {
            SetTTL_action;
            Fallback_action;
            Drop_action;
        }
        default_action = SetTTL_action;
        implementation = hash_table(64);
    }

    apply {
		if (hd.ipv4.isValid())
		{
			counters.increment((bit<32>)hd.ipv4.dstAddr);
		}
        dstmactable.apply();
        xout.output_port = 0;
        xout.output_action = xoutdrop ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
    }
}

control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;
