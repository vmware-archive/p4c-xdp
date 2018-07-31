#!/usr/bin/env python
# Copyright 2013-present Barefoot Networks, Inc.
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

""" Contains different eBPF models and specifies their individual behavior
    Currently five phases are defined:
   1. Invokes the specified compiler on a provided p4 file.
   2. Parses an stf file and generates an pcap output.
   3. Loads the generated template or compiles it to a runnable binary.
   4. Feeds the generated pcap test packets into the P4 "filter"
   5. Evaluates the output with the expected result from the .stf file
"""

import os
import sys
from glob import glob
from ebpfenv import Bridge
sys.path.insert(0, os.path.dirname(
    os.path.abspath(__file__)) + '/../../tools')
sys.path.insert(0, os.path.dirname(
    os.path.abspath(__file__)) + '/../../backends/ebpf/targets')
from kernel_target import Target as EBPFKernelTarget
from testutils import *


class Target(EBPFKernelTarget):
    def __init__(self, tmpdir, options, template, outputs):
        EBPFKernelTarget.__init__(self, tmpdir, options, template, outputs)

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

    def compile_p4(self, argv):
        """ Compile the p4 target """
        if not os.path.isfile(self.options.p4filename):
            raise Exception("No such file " + self.options.p4filename)
        # Initialize arguments for the makefile
        args = self.get_make_args(self.runtimedir, self.options.target)
        # name of the makefile target
        args += self.template + ".c "
        # name of the output source file
        args += "BPFOBJ=" + self.template + ".c "
        # location of the P4 input file
        args += "P4FILE=" + self.options.p4filename + " "
        # location of the P4 compiler
        args += "P4C=" + self.options.compilerSrcDir + "/build/p4c-xdp "
        p4_args = ' '.join(map(str, argv))
        if (p4_args):
            # Remaining arguments
            args += "P4ARGS=\"" + p4_args + "\" "
        errmsg = "Failed to compile P4:"
        result = run_timeout(self.options.verbose, args, TIMEOUT,
                             self.outputs, errmsg)
        if result != SUCCESS:
            # If the compiler crashed fail the test
            if 'Compiler Bug' in open(self.outputs["stderr"]).readlines():
                sys.exit(FAILURE)

        # Check if we expect the p4 compilation of the p4 file to fail
        expected_error = is_err(self.options.p4filename)
        if expected_error:
            # We do, so invert the result
            if result == SUCCESS:
                result = FAILURE
            else:
                result = SUCCESS
        return result, expected_error

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

    def _create_bridge(self):
        # The namespace is the id of the process
        namespace = str(os.getpid())
        # Create the namespace and the bridge with all its ports
        br = Bridge(namespace, self.outputs, self.options.verbose)
        result = br.create_virtual_env(len(self.expected))
        if result != SUCCESS:
            br.ns_del()
            return None
        return br

    def _get_run_cmd(self):
        direction = "in"
        pcap_pattern = self.filename('', direction)
        num_files = len(glob(self.filename('*', direction)))
        report_output(self.outputs["stdout"],
                      self.options.verbose,
                      "Input file: %s" % pcap_pattern)
        # Main executable
        cmd = self.template + " "
        # Input pcap pattern
        cmd += "-f " + pcap_pattern + " "
        # Number of input interfaces
        cmd += "-n " + str(num_files) + " "
        # Debug flag (verbose output)
        cmd += "-d"
        return cmd

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
        # Check if eBPF maps have actually been created
        result = bridge.ns_proc_write(proc,
                                      "ls -1 /sys/fs/bpf/tc/globals")
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
