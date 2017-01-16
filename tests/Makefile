LLC ?= llc
CLANG ?= clang
CC= gcc
CFLAGS=-g
BPFOBJ= two_ebpf.o hit_ebpf.o switch_ebpf.o count_ebpf.o 
IFACE=enp0s16
P4C=/root/p4c/build/p4c-ebpf-sw

all: $(BPFOBJ) verify_target_bpf

# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else \
			echo "pass verify_cmds:" \
			true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else \
		echo "pass verify_target_bpf:" \
		true; fi

load:
	@ip link show $(IFACE); \
	for TOOL in $(BPFOBJ); do \
		ip link set dev $(IFACE) xdp obj $${TOOL} verb; \
		ip link set dev $(IFACE) xdp off; \
	done

# P4 generate .c
# keep the intermediate .c file
.PRECIOUS: %.c
%.c: %.p4
	@if ! ($(P4C) --help > /dev/null 2>&1); then \
		echo "*** ERROR: Cannot find p4c-ebpf-sw"; \
		exit 1;\
	fi;\
	$(P4C) --target xdp -o $@ $<;

# BPF program
%.o: %.c
	$(CLANG) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-O2 -emit-llvm -g -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

clean:
	@rm -f *.o *.c

