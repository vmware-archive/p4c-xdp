#!/usr/bin/env python
# Copyright 2018 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
# path to the tools folder of the compiler
sys.path.insert(0, os.path.dirname(
    os.path.abspath(__file__)) + '/../../tools')
# path to the framework repository of the compiler
sys.path.insert(0, os.path.dirname(
    os.path.abspath(__file__)) + '/../../backends/ebpf/targets')
from kernel_target import Target as EBPFKernelTarget
from testutils import *


class Target(EBPFKernelTarget):
    def __init__(self, tmpdir, options, template, outputs):
        EBPFKernelTarget.__init__(self, tmpdir, options, template, outputs)
        # We use a different compiler, override the inherited default
        self.compiler = self.options.compilerdir + "/build/p4c-xdp"

    def create_filter(self):
        # Use clang to compile the generated C code to a LLVM IR
        args = "make "
        # target makefile
        args += "-f kernel.mk "
        # Source folder of the makefile
        args += "-C " + self.runtimedir + " "
        # Input eBPF byte code
        args += self.template + ".o "
        # The bpf program to attach to the interface
        args += "BPFOBJ=" + self.template + ".o "
        args += "INCLUDES+=-I" + os.path.dirname(self.options.p4filename)
        errmsg = "Failed to compile the eBPF byte code:"
        return run_timeout(self.options.verbose, args, TIMEOUT,
                           self.outputs, errmsg)

    def _create_runtime(self):
        args = self.get_make_args(self.runtimedir, "kernel")
        # List of bpf programs to attach to the interface
        args += "BPFOBJ=" + self.template + " "
        args += "CFLAGS+=-DCONTROL_PLANE "
        args += "INCLUDES+=-I" + os.path.dirname(self.options.p4filename)
        args += " SOURCES= "
        errmsg = "Failed to build the filter:"
        return run_timeout(self.options.verbose, args, TIMEOUT,
                           self.outputs, errmsg)

    def _ip_load_cmd(self, bridge, proc, port_name):
        # Load the specified eBPF object to "port_name" ingress and egress
        # As a side-effect, this may create maps in /sys/fs/bpf/tc/globals
        cmd = ("ip link set dev %s xdp obj %s verb " %
               (port_name, self.template + ".o"))
        return bridge.ns_proc_write(proc, cmd)

    def _run_in_namespace(self, bridge):
        # Open a process in the new namespace
        proc = bridge.ns_proc_open()
        if not proc:
            return FAILURE
        # Get the command to load eBPF code to all the attached ports
        if len(bridge.br_ports) > 0:
            for port in bridge.br_ports:
                result = self._ip_load_cmd(bridge, proc, port)
                bridge.ns_proc_append(proc, "")
        else:
            # No ports attached (no pcap files), load to bridge instead
            result = self._ip_load_cmd(bridge, proc, bridge.br_name)
            bridge.ns_proc_append(proc, "")

        if result != SUCCESS:
            return result
        # Finally, append the actual runtime command to the process
        result = bridge.ns_proc_append(proc, self._get_run_cmd())
        if result != SUCCESS:
            return result
        # Execute the command queue and close the process, retrieve result
        return bridge.ns_proc_close(proc)

    def run(self):
        # Root is necessary to load ebpf into the kernel
        require_root(self.outputs)
        result = self._create_runtime()
        if result != SUCCESS:
            return result
        # Create the namespace and the central testing bridge
        bridge = self._create_bridge()
        if not bridge:
            return FAILURE
        # Run the program in the generated namespace
        result = self._run_in_namespace(bridge)
        bridge.ns_del()
        return result
