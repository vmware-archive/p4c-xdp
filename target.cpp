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

#include "target.h"

namespace XDP {

void XdpTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
    builder->append(
        "#define KBUILD_MODNAME \"xdptest\"\n"
        "#include <linux/bpf.h>\n"
        "#include \"bpf_helpers.h\"\n"
        "\n"
        "#define load_byte(data, b)  (*(u8 *)(data + (b)))\n"
        "#define load_half(data, b) __constant_ntohs(*(u16 *)(data + (b)))\n"
        "#define load_word(data, b) __constant_ntohl(*(u32 *)(data + (b)))\n"
        "#define htonl(d) __constant_htonl(d)\n"
        "#define htons(d) __constant_htons(d)\n");
}

void XdpTarget::emitMain(Util::SourceCodeBuilder* builder,
                         cstring functionName,
                         cstring argName) const {
    builder->appendFormat("int %s(struct xdp_md* %s)", functionName, argName);
}

void XdpTarget::emitTableDecl(Util::SourceCodeBuilder* builder,
                              cstring tblName, bool isHash,
                              cstring keyType, cstring valueType,
                              unsigned size) const {
    builder->emitIndent();
    builder->appendFormat("struct bpf_map_def SEC(\"maps\") %s = ", tblName);
    builder->blockStart();
    builder->emitIndent();
    builder->append(".type = ");
    if (isHash)
        builder->appendLine("BPF_MAP_TYPE_HASH,");
    else
        builder->appendLine("BPF_MAP_TYPE_ARRAY,");

    builder->emitIndent();
    builder->appendFormat(".key_size = sizeof(%s), ", keyType);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".value_size = sizeof(%s), ", valueType);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".max_entries = %d, ", size);
    builder->newline();

    builder->blockEnd(false);
    builder->endOfStatement(true);
}

}  // namespace XDP
