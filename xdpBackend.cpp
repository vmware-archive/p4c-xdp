/*
Copyright 2017 VMware, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "lib/error.h"
#include "lib/nullstream.h"
#include "frontends/p4/evaluator/evaluator.h"

#include "xdpBackend.h"
#include "xdpProgram.h"
#include "target.h"
#include "backends/ebpf/ebpfType.h"

namespace XDP {

void run_xdp_backend(const EbpfOptions& options, const IR::ToplevelBlock* toplevel,
                      P4::ReferenceMap* refMap, P4::TypeMap* typeMap) {
    if (toplevel == nullptr)
        return;

    auto main = toplevel->getMain();
    if (main == nullptr) {
        ::error("Could not locate top-level block; is there a %1% module?", IR::P4Program::main);
        return;
    }

    EBPF::Target* target;
    if (options.target == "bcc") {
        target = new EBPF::BccTarget();
    } else if (options.target == "kernel") {
        target = new EBPF::KernelSamplesTarget();
    } else if (options.target.isNullOrEmpty() || options.target == "xdp") {
        target = new XdpTarget();
    } else {
        ::error("Unknown target %s; legal choices are 'bcc', 'xdp', and 'kernel'", options.target);
        return;
    }

    EBPF::CodeBuilder builder(target);
    EBPF::EBPFTypeFactory::createFactory(typeMap, &builder);
    auto prog = new XDPProgram(toplevel->getProgram(), refMap, typeMap, toplevel, &builder);
    if (!prog->build())
        return;

    if (options.outputFile.isNullOrEmpty())
        return;
    auto stream = openFile(options.outputFile, false);
    if (stream == nullptr)
        return;

    prog->emit();
    *stream << builder.toString();
    stream->flush();
}

}  // namespace XDP
