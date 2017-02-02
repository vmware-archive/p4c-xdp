# Makefile for the XDP P4-16 back-end.
# To be included in the main P4C compiler makefile

bin_PROGRAMS += p4c-xdp
p4c_xdp_LDADD = libfrontend.la libp4ctoolkit.a

p4c_xdp_UNIFIED = \
	extensions/p4c-xdp/p4c-xdp.cpp \
	extensions/p4c-xdp/xdpModel.cpp \
	extensions/p4c-xdp/xdpControl.cpp \
	extensions/p4c-xdp/xdpProgram.cpp \
	extensions/p4c-xdp/target.cpp \
	extensions/p4c-xdp/xdpBackend.cpp \
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
	extensions/p4c-xdp/xdpModel.h \
	extensions/p4c-xdp/xdpProgram.h \
	extensions/p4c-xdp/xdpControl.h \
	extensions/p4c-xdp/target.h \
	extensions/p4c-xdp/xdpBackend.h

cpplint_FILES += $(p4c_xdp_UNIFIED) $(p4c_xdp_NONUNIFIED)
