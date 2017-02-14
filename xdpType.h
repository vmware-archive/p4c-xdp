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

#ifndef _EXTENSIONS_P4C_XDP_XDPTYPE_H_
#define _EXTENSIONS_P4C_XDP_XDPTYPE_H_

#include "backends/ebpf/ebpfType.h"

namespace XDP {

class XDPTypeFactory : public EBPF::EBPFTypeFactory {
 protected:
    explicit XDPTypeFactory(const P4::TypeMap* typeMap) : EBPFTypeFactory(typeMap) {}
 public:
    static void createFactory(const P4::TypeMap* typeMap)
    { EBPFTypeFactory::instance = new XDPTypeFactory(typeMap); }
    EBPF::EBPFType* create(const IR::Type* type) override;
};

class XDPEnumType : public EBPF::EBPFType, public EBPF::IHasWidth {
 public:
    explicit XDPEnumType(const IR::Type_Enum* type) : EBPFType(type) {}
    void emit(EBPF::CodeBuilder* builder) override;
    void declare(EBPF::CodeBuilder* builder, cstring id, bool asPointer) override;
    void emitInitializer(EBPF::CodeBuilder* builder) override
    { builder->append("0"); }
    unsigned widthInBits() override { return 32; }
    unsigned implementationWidthInBits() override { return 32; }

    const IR::Type_Enum* getType() const { return type->to<IR::Type_Enum>(); }
};

}  // namespace XDP

#endif /* _EXTENSIONS_P4C_XDP_XDPTYPE_H_ */
