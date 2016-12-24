#!/bin/bash
set -x
set -e
# OVS BPF script for attaching to tc
# filename: tmp.o 
# section name: _ebpf_filter

DEV=enp0s16

tc qdisc add dev $DEV clsact
tc filter add dev $DEV ingress bpf da obj tmp.o sec _ebpf_filter verb 
#tc qdisc delete dev $DEV clsact
#tc filter add dev $DEV egress bpf da obj tcbpf_ovs.o sec ovs_egress

exit
#tc qdisc delete dev $DEV clsact
#tc filter add dev $DEV egress bpf da obj tcbpf_ovs.o exp /tmp/bpf-uds sec ovs_ingress 
