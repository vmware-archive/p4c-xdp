/*
Copyright 2013-present Barefoot Networks, Inc.

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

#ifndef _EXTENSIONS_P4C_XDP_XDPPROGRAM_H_
#define _EXTENSIONS_P4C_XDP_XDPPROGRAM_H_

#include "target.h"
#include "xdpModel.h"
#include "ir/ir.h"
#include "frontends/p4/typeMap.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "backends/ebpf/ebpfObject.h"
#include "backends/ebpf/ebpfOptions.h"
#include "backends/ebpf/ebpfProgram.h"

namespace XDP {

class XDPDeparser;
class XDPSwitch;

class XDPProgram : public EBPF::EBPFProgram {
 public:
    // If the deparser is missing we are still
    // compiling for the old EBPF model.
    XDPDeparser* deparser;
    XDPModel&    xdp_model;
    cstring outHeaderLengthVar;
    cstring outTableName;

    XDPProgram(const EbpfOptions& options, const IR::P4Program* program,
               P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
               const IR::ToplevelBlock* toplevel) :
            EBPF::EBPFProgram(options, program, refMap, typeMap, toplevel),
            deparser(nullptr), xdp_model(XDPModel::instance) {
        outHeaderLengthVar = EBPF::EBPFModel::reserved("outHeaderLength");
        outTableName = EBPF::EBPFModel::reserved("outTable");
    }

    // If the deparser is null we are compiling for the old EBPF model
    bool switchTarget() const { return deparser != nullptr; }

    void emitC(EBPF::CodeBuilder* builder, cstring headerFile) override;
    bool build() override;  // return 'true' on success
    void emitLocalVariables(EBPF::CodeBuilder* builder) override;
    void emitPipeline(EBPF::CodeBuilder* builder) override;
    XDPSwitch* getSwitch() const;
    void emitTypes(EBPF::CodeBuilder* builder) override;
};

}  // namespace XDP

#endif /* _EXTENSIONS_P4C_XDP_XDPPROGRAM_H_ */
