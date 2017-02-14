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

#include "xdpType.h"

namespace XDP {

EBPF::EBPFType* XDPTypeFactory::create(const IR::Type* type) {
    if (type->is<IR::Type_Enum>()){
        return new XDPEnumType(type->to<IR::Type_Enum>());
    }
    return EBPFTypeFactory::create(type);
}

void XDPEnumType::declare(EBPF::CodeBuilder* builder, cstring id, bool asPointer) {
    builder->append("enum ");
    builder->append(getType()->name);
    if (asPointer)
        builder->append("*");
    builder->append(" ");
    builder->append(id);
}

void XDPEnumType::emit(EBPF::CodeBuilder* builder) {
    builder->append("enum ");
    auto et = getType();
    builder->append(et->name);
    builder->blockStart();
    for (auto m : *et->members) {
        builder->append(m->name);
        builder->appendLine(",");
    }
    builder->blockEnd(true);
}


}  // namespace XDP
