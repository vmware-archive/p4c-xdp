# Makefile for the EBPF P4-16 back-end.
# To be included in the main P4C compiler makefile

bin_PROGRAMS += p4c-ebpf-sw
p4c_ebpf_sw_LDADD = libfrontend.a libp4ctoolkit.a

p4c_ebpf_sw_UNIFIED = \
	extensions/p4c-ovs-ebpf/p4c-ebpf-sw.cpp \
	extensions/p4c-ovs-ebpf/ebpfBackend.cpp \
	extensions/p4c-ovs-ebpf/ebpfObject.cpp \
	extensions/p4c-ovs-ebpf/ebpfTable.cpp \
	extensions/p4c-ovs-ebpf/ebpfControl.cpp \
	extensions/p4c-ovs-ebpf/ebpfParser.cpp \
	extensions/p4c-ovs-ebpf/target.cpp \
	extensions/p4c-ovs-ebpf/ebpfType.cpp \
	extensions/p4c-ovs-ebpf/codeGen.cpp \
	extensions/p4c-ovs-ebpf/ebpfModel.cpp \
	extensions/p4c-ovs-ebpf/midend.cpp

noinst_HEADERS += \
	extensions/p4c-ovs-ebpf/codeGen.h \
	extensions/p4c-ovs-ebpf/ebpfBackend.h \
	extensions/p4c-ovs-ebpf/ebpfControl.h \
	extensions/p4c-ovs-ebpf/ebpfModel.h \
	extensions/p4c-ovs-ebpf/ebpfObject.h \
	extensions/p4c-ovs-ebpf/ebpfOptions.h \
	extensions/p4c-ovs-ebpf/ebpfParser.h \
	extensions/p4c-ovs-ebpf/ebpfTable.h \
	extensions/p4c-ovs-ebpf/ebpfType.h \
	extensions/p4c-ovs-ebpf/midend.h \
	extensions/p4c-ovs-ebpf/target.h

cpplint_FILES += $(p4c_ebpf_sw_UNIFIED) $(p4c_ebpf_sw_NONUNIFIED)

