# p4c-ovs-ebpf

Backend for the P4 compiler targeting ebpf, currently for both tc and XDP.;
intended to implemenet much of the OVS functionalituy.
This should be built as a back-end to the P4-16 compiler from http://github.com/p4lang/p4c

## TC: Linux Traffic Control
TC is Linux's QoS subsystem for traffic shaping and policing. eBPF program can be attached to
a tc classifier as a hook point for eBPF bytecode execution. Use:

  ./p4c-ovs-ebpf --target ebpf -o <p4.c> <p4 program> 

then you need to compile this <p4.c> to eBPF bytecode, then loaded into Linux tc

	tc qdisc add dev $DEV clsact

	tc filter add dev $DEV ingress bpf obj p4.o sec ingress verb

to unload

	tc qdisc delete dev $DEV clsact

## XDP: eXpress Data Path
XDP is a packet processing mechanism implemented within the device driver with eBPF.  Currently this
project supports 

  ./p4c-ovs-ebpf --target xdp -o <p4.c>  <P4 program>

then you need to compile this <p4.c> to eBPF bytecode, then loaded into your driver:

    ip link set dev $DEV xdp obj p4.o verb

to unload

    ip link set dev $DEV xdp off

## ISSUES
see issues

## TODO
- remove dependencies with Linux kernel headers
- more test cases from P4 to XDP
- add deparser supports

