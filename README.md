# p4c-xdp
[![Build Status](https://travis-ci.org/williamtu/p4c-xdp.svg?branch=master)](https://travis-ci.org/williamtu/p4c-xdp)

This work presents a P4 compiler backend targeting XDP, the eXpress Data Path.
P4 is a domain-specific language describing how packets are processed by the
data plane of a programmable network elements, including network interface
cards, appliances, and virtual switches.  With P4, programmers focus on
defining the protocol parsing, matching, and action executions, instead
of the platform-specific language or implementation details.
 
XDP is designed for users who want programmability as well as performance.
XDP allows users to write a C-like  packet processing program and loads into
the device driver's receiving queue.  When the device observes an incoming
packet, before hanging the packet to the Linux stack, the user-defined XDP
program is triggered to execute against the packet payload, making the
decision as early as possible.

We bring together the benefits of the two: P4 and XDP.  To get started,
first you need to setup the P4-16 compiler, then this project
is an extension to the P4-16. To execute the XDP, you need Linux kernel
version >= 4.10.0-rc7+ due to some BPF verifier limitations

## Installation
### Docker
Please see Dockerfile. There is also a public docker image available as u9012063/p4xdp
$ docker pull u9012063/p4xdp
will pull the latest image

### P4-16 Compiler
First you need to follow the installation guide of [P4-16](https://github.com/p4lang/p4c/)
When you have P4-16 compiler, then add this project as an extension.
Assuming you have P4-16 at your dir  ~/p4c/, to setup P4C-XDP:
```bash
cd ~/p4c/
mkdir extensions
cd extensions
git clone https://github.com/williamtu/p4c-xdp.git
```
Now you have p4c-xdp at ~/p4c/extensions/p4c-xdp, next is to
recompile p4c
```bash
cd ~/p4c/
./bootstrap.sh
cd ~/p4c/build/
make
```
Then you will have p4c-xdp binary at ~/p4c/build
Next is to create a soft link to the binary
```bash
cd ~/p4c/extensions/p4c-xdp
ln -s ~/p4c/build/p4c-xdp p4c-xdp
```
under tests, 'make' will check you llvm and clang version,
compile all .p4 file, generate .c file, and loading into kernel
to check BPF verifier

## XDP: eXpress Data Path
XDP is a packet processing mechanism implemented within the device driver with eBPF.  Currently this
project supports
```bash
	./p4c-xdp --target xdp -o /tmp/xdp1.c xdp1.p4 
```
then you need to compile this <xdp1.c> to eBPF bytecode, xdp1.o, then loaded into your driver:
```bash
    ip link set dev $DEV xdp obj xdp1.o verb
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
		-O2 -emit-llvm -g -c /tmp/xdp1.c -o -| llc -march=bpf -filetype=obj -o /tmp/xdp1.o
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
