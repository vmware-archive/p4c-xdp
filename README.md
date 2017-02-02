# p4c-xdp

Backend for the P4 compiler targeting XDP.  This should be built as a
back-end to the P4-16 compiler from http://github.com/p4lang/p4c

## Installation
First you need the P4-16, then this project is an extension to the P4-16
Kernel version: 4.10+ due to some BPF verifier limitations

```bash
git clone http://github.com/p4lang/p4c
cd p4c
./bootstrap.sh
mkdir build
cd build
make
```
Now you have P4-16 compiler, then add this project as an extension, under p4c
```bash
mkdir extensions
cd extensions
git clone https://github.com/williamtu/p4c-ovs-ebpf.git
cd p4c-ovs-ebpf/
cd tests/
make
```
under tests, 'make' will check you llvm and clang version,
compile all .p4 file, generate .c file, and loading into kernel
to check BPF verifier

## TC: Linux Traffic Control
TC is Linux's QoS subsystem for traffic shaping and policing. eBPF program can be attached to
a tc classifier as a hook point for eBPF bytecode execution. Use:

```bash
	./p4c-xdp --target ebpf -o <p4.c> <p4 program>
```
then you need to compile this <p4.c> to eBPF bytecode, then loaded into Linux tc
```bash
	tc qdisc add dev $DEV clsact
	tc filter add dev $DEV ingress bpf obj p4.o sec ingress verb
```
to unload
```bash
	tc qdisc delete dev $DEV clsact
```
## XDP: eXpress Data Path
XDP is a packet processing mechanism implemented within the device driver with eBPF.  Currently this
project supports
```bash
	./p4c-xdp --target xdp -I /root/p4c/p4include/ -I /root/p4c/backends/ebpf/p4include/ -o /tmp/x.c xdp1.p4 
```
then you need to compile this <p4.c> to eBPF bytecode, then loaded into your driver:
```bash
    ip link set dev $DEV xdp obj p4.o verb
```
to unload
```bash
    ip link set dev $DEV xdp off
```
to compile a single .c file
```bash
clang -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-tautological-compare \
		-O2 -emit-llvm -g -c /tmp/x.c -o -| llc -march=bpf -filetype=obj -o /tmp/x.o
```

## TODO
- test the new xdp model
- improve documentation (make headers_install ARCH= HDR_INSTALL_PATH=)
- more test cases from P4 to XDP
- introduce extern function, bpf_perf_event_output for sending data to userspace
- add a docker or vagrant box for testing?
- support for checksum
- add userspace test
- initialize xin somehow. Where is the input port for xdp
