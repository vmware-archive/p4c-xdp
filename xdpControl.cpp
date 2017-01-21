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

#include "xdpControl.h"
#include "lib/error.h"
#include "backends/ebpf/ebpfControl.h"

namespace XDP {

XDPSwitch::XDPSwitch(const XDPProgram* program,
                     const IR::ControlBlock* block,
                     const IR::Parameter* parserHeaders) :
        EBPF::EBPFControl(program, block, parserHeaders),
        inputMeta(nullptr), outputMeta(nullptr) {}

bool XDPSwitch::build() {
    hitVariable = program->refMap->newName("hit");
    auto pl = controlBlock->container->type->applyParams;
    if (pl->size() != 3) {
        ::error("Expected switch block to have exactly 3 parameters");
        return false;
    }

    auto it = pl->parameters->begin();
    headers = *it;
    ++it;
    inputMeta = *it;
    ++it;
    outputMeta = *it;

    scanConstants();
    return ::errorCount() == 0;
}

//////////////////////////////////////////////////////////////////////////

XDPDeparser::XDPDeparser(const XDPProgram* program,
                         const IR::ControlBlock* block,
                         const IR::Parameter* parserHeaders) :
        EBPF::EBPFControl(program, block, parserHeaders), packet(nullptr) {}

bool XDPDeparser::build() {
    hitVariable = program->refMap->newName("hit");
    auto pl = controlBlock->container->type->applyParams;
    if (pl->size() != 2) {
        ::error("Expected switch block to have exactly 3 parameters");
        return false;
    }

    auto it = pl->parameters->begin();
    headers = *it;
    ++it;
    packet = *it;

    return true;
}

}  // namespace XDP
