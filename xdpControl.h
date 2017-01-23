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

#ifndef _EXTENSIONS_P4C_OVS_EBPF_XDPCONTROL_H_
#define _EXTENSIONS_P4C_OVS_EBPF_XDPCONTROL_H_

#include "backends/ebpf/ebpfControl.h"
#include "xdpProgram.h"

namespace XDP {

class XDPSwitch : public EBPF::EBPFControl {
 public:
    const IR::Parameter*    inputMeta;
    const IR::Parameter*    outputMeta;

    XDPSwitch(const XDPProgram* program, const IR::ControlBlock* block,
              const IR::Parameter* parserHeaders);
    bool build() override;
};

class XDPDeparser : public EBPF::EBPFControl {
 public:
    const IR::Parameter*    packet;

    XDPDeparser(const XDPProgram* program, const IR::ControlBlock* block,
                const IR::Parameter* parserHeaders);
    bool build() override;
};

}  // namespace XDP

#endif /* _EXTENSIONS_P4C_OVS_EBPF_XDPCONTROL_H_ */
