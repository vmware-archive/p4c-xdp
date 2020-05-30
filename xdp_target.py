#!/usr/bin/env python3
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

import sys
# path to the tools folder of the compiler
sys.path.insert(0, 'p4c/tools')
# path to the framework repository of the compiler
sys.path.insert(0, 'p4c/backends/ebpf/targets')
from .kernel_target import Target as EBPFKernelTarget
from testutils import *


class Target(EBPFKernelTarget):
    EBPF_MAP_PATH = "/sys/fs/bpf/xdp/globals"

    def __init__(self, tmpdir, options, template, outputs):
        EBPFKernelTarget.__init__(self, tmpdir, options, template, outputs)
        # We use a different compiler, override the inherited default
        components = options.compiler.split("/")[0:-1]
        self.compiler = "/".join(components) + "/p4c-xdp"
        print("Compiler is", self.compiler)

    def compile_dataplane(self):
        old_target = self.options.target
        self.options.target = "kernel"
        super(Target, self).compile_dataplane()
        self.options.target = old_target

    def _create_runtime(self):
        old_target = self.options.target
        self.options.target = "kernel"
        super(Target, self)._create_runtime()
        self.options.target = old_target

    def _load_filter(self, bridge, proc, port_name):
        # Load the specified eBPF object to "port_name" ingress and egress
        # As a side-effect, this may create maps in /sys/fs/bpf/
        cmd = ("ip link set dev %s xdp obj %s verb" %
               (port_name, self.template + ".o"))
        return bridge.ns_proc_write(proc, cmd)

    def _attach_filters(self, bridge, proc):
        # Get the command to load XDP code to all the attached ports
        # We load XDP directly to the bridge ports instead of the edges as with tc
        if len(bridge.br_ports) > 0:
            for port in bridge.br_ports:
                result = self._load_filter(bridge, proc, port)
                bridge.ns_proc_append(proc, "")
        else:
            # No ports attached (no pcap files), load to bridge instead
            result = self._load_filter(bridge, proc, bridge.br_name)
            bridge.ns_proc_append(proc, "")
        if result != SUCCESS:
            return result
        return SUCCESS
