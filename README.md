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

<p align="center">
  <img src="doc/images/p4xdp-workflow.png" />
</p>

## Installation
### Docker/Vagrant
Please see Dockerfile. There is also a public docker image available as u9012063/p4xdp
```bash
$ docker pull u9012063/p4xdp
```
will pull the latest image. However, the XDP BPF code has dependency on your kernel version.
Currently for some complicated cases we require kernel >= 4.10.0-rc7.  So a vagrant box is 
also provided with kernel 4.10.0-rc8.
```bash
$ vagrant up
$ vagrant ssh
ubuntu@ubuntu-xenial:~$ sudo su
root@ubuntu-xenial:/home/ubuntu# docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
u9012063/p4xdp      latest              3c77fbbd84e5        41 hours ago        2.469 GB
root@ubuntu-xenial:/home/ubuntu# docker run -it -u root --privileged <IMAGE ID>
```
Will boot this VM, pull the docker image, and you can try p4c-xdp.

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
XDP is a packet processing mechanism implemented within the device driver with eBPF.
Currently to compile a P4 to C program, uses
```bash
	# ./p4c-xdp --target xdp -o <output_c_file> <input_p4>
	./p4c-xdp --target xdp -o /tmp/xdp1.c xdp1.p4 
```
then you need to compile the xdp1.c to eBPF bytecode, xdp1.o, then loaded
into your driver. To compile a single .c file
```bash
clang -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-tautological-compare \
		-O2 -emit-llvm -g -c /tmp/xdp1.c -o -| llc -march=bpf -filetype=obj -o /tmp/xdp1.o
```
Then loaded into driver with XDP support
```bash
    ip link set dev $DEV xdp obj xdp1.o verb
```
to unload the XDP object
```bash
    ip link set dev $DEV xdp off
```
## Sample Code
Please see the [tests folder](https://github.com/williamtu/p4c-xdp/tree/master/tests)
Simply run 'make' will start the build

