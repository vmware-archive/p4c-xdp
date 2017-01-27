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

#ifndef _EXTENSIONS_P4C_OVS_EBPF_TARGET_H_
#define _EXTENSIONS_P4C_OVS_EBPF_TARGET_H_

#include "backends/ebpf/target.h"

namespace XDP {

// Target XDP
class XdpTarget : public EBPF::KernelSamplesTarget {
 public:
    XdpTarget() : KernelSamplesTarget("XDP") {}
    void emitIncludes(Util::SourceCodeBuilder* builder) const override;
    void emitMain(Util::SourceCodeBuilder* builder,
                  cstring functionName,
                  cstring argName) const override;
    cstring dataOffset(cstring base) const override
    { return cstring("((void*)(long)")+ base + "->data)"; }
    void emitTableDecl(Util::SourceCodeBuilder* builder,
                       cstring tblName, bool isHash,
                       cstring keyType, cstring valueType, unsigned size) const override;
    cstring dataEnd(cstring base) const override
    { return cstring("((void*)(long)")+ base + "->data_end)"; }
    void emitCodeSection(Util::SourceCodeBuilder* builder, cstring) const override
    { EBPF::KernelSamplesTarget::emitCodeSection(builder, "prog"); }
    cstring forwardReturnCode() const override { return "XDP_PASS"; }
    cstring dropReturnCode() const override { return "XDP_DROP"; }
    cstring abortReturnCode() const override { return "XDP_ABORTED"; }
};

}  // namespace XDP

#endif /* _EXTENSIONS_P4C_OVS_EBPF_TARGET_H_ */
