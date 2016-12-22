#!/bin/bash
KERNEL=/root/net-next/

echo "ebpf filename:" $1

clang  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5.4.0/include/ \
  -I../ -I$KERNEL/arch/x86/include -I$KERNEL/arch/x86/include/generated/uapi \
  -I$KERNEL/arch/x86/include/generated  -I$KERNEL/include \
  -I$KERNEL/arch/x86/include/uapi \
  -I$KERNEL/include/uapi -I$KERNEL/include/generated/uapi \
  -include $KERNEL/include/linux/kconfig.h \
  -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types -emit-llvm -O2 -c $1 -o -| \
  llc -march=bpf -filetype=obj -o tmp.o

echo "output to tmp.o"

exit 0
./p4test --p4-14 ../backends/p4c-ovs-ebpf/ovs-parse.p4 
./p4test --pp x.p4 --p4-14 ../backends/p4c-ovs-ebpf/ovs-parse.p4 

