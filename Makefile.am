# Makefile for the XDP P4-16 back-end.
# To be included in the main P4C compiler makefile

bin_PROGRAMS += p4c-xdp
p4c_xdp_LDADD = libfrontend.la libp4ctoolkit.a

p4c_xdp_UNIFIED = \
	extensions/p4c-ovs-ebpf/p4c-xdp.cpp \
	extensions/p4c-ovs-ebpf/xdpModel.cpp \
	extensions/p4c-ovs-ebpf/xdpControl.cpp \
	extensions/p4c-ovs-ebpf/xdpProgram.cpp \
	extensions/p4c-ovs-ebpf/target.cpp \
	extensions/p4c-ovs-ebpf/xdpBackend.cpp \
	backends/ebpf/ebpfProgram.cpp \
	backends/ebpf/ebpfTable.cpp \
	backends/ebpf/ebpfControl.cpp \
	backends/ebpf/ebpfParser.cpp \
	backends/ebpf/target.cpp \
	backends/ebpf/ebpfType.cpp \
	backends/ebpf/codeGen.cpp \
	backends/ebpf/ebpfModel.cpp \
	backends/ebpf/midend.cpp

noinst_HEADERS += \
	extensions/p4c-ovs-ebpf/xdpModel.h \
	extensions/p4c-ovs-ebpf/xdpProgram.h \
	extensions/p4c-ovs-ebpf/xdpControl.h \
	extensions/p4c-ovs-ebpf/target.h \
	extensions/p4c-ovs-ebpf/xdpBackend.h

cpplint_FILES += $(p4c_xdp_UNIFIED) $(p4c_xdp_NONUNIFIED)
