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

#include "target.h"

namespace EBPF {

void KernelSamplesTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
    builder->append(
        "#include <linux/bpf.h>\n"
        "/* TODO: these should be in some header somewhere in the kernel, but where? */\n"
        "#define SEC(NAME) __attribute__((section(NAME), used))\n"
        "static void *(*bpf_map_lookup_elem)(void *map, void *key) =\n"
        "        (void *) BPF_FUNC_map_lookup_elem;\n"
        "unsigned long long load_byte(void *skb,\n"
        "                             unsigned long long off) asm(\"llvm.bpf.load.byte\");\n"
        "unsigned long long load_half(void *skb,\n"
        "                             unsigned long long off) asm(\"llvm.bpf.load.half\");\n"
        "unsigned long long load_word(void *skb,\n"
        "                             unsigned long long off) asm(\"llvm.bpf.load.word\");\n"
        "struct bpf_map_def {\n"
        "        __u32 type;\n"
        "        __u32 key_size;\n"
        "        __u32 value_size;\n"
        "        __u32 max_entries;\n"
        "        __u32 flags;\n"
        "        __u32 id;\n"
        "        __u32 pinning;\n"
        "};\n"
        "SEC(\"_ebpf_filter\") int ebpf_filter(struct __sk_buff *skb);\n"
        "\n"
        "static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =\n"
        "                              (void *) BPF_FUNC_trace_printk;\n"
        "#define printk(fmt, ...)    \\\n"
        "({  char ___fmt[] = fmt;    \\\n"
        "    bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\\\n"
        "})\n"
        );
}

void KernelSamplesTarget::emitTableLookup(Util::SourceCodeBuilder* builder, cstring tblName,
                                          cstring key, cstring value) const {
    builder->appendFormat("%s = bpf_map_lookup_elem(&%s, &%s)",
                          value, tblName, key);
}

void KernelSamplesTarget::emitTableUpdate(Util::SourceCodeBuilder* builder, cstring tblName,
                                          cstring key, cstring value) const {
    builder->appendFormat("bpf_map_update_elem(&%s, &%s, &%s, BPF_ANY);",
                          tblName, key, value);
}

void KernelSamplesTarget::emitTableDecl(Util::SourceCodeBuilder* builder,
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
    builder->appendFormat(".pinning = 2, //PIN_GLOBAL_NS");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".max_entries = %d, ", size);
    builder->newline();

    builder->blockEnd(false);
    builder->endOfStatement(true);
}

void KernelSamplesTarget::emitLicense(Util::SourceCodeBuilder* builder, cstring license) const {
    builder->emitIndent();
    builder->appendFormat("char _license[] SEC(\"license\") = \"%s\";", license);
    builder->newline();
}

void KernelSamplesTarget::emitCodeSection(
    Util::SourceCodeBuilder* builder, cstring sectionName) const {
    builder->appendFormat("SEC(\"%s\")\n", sectionName);
}

void KernelSamplesTarget::emitMain(Util::SourceCodeBuilder* builder,
                                   cstring functionName,
                                   cstring argName) const {
    builder->appendFormat("int %s(struct __sk_buff* %s)", functionName, argName);
}

//////////////////////////////////////////////////////////////

void BccTarget::emitTableLookup(Util::SourceCodeBuilder* builder, cstring tblName,
                                cstring key, cstring value) const {
    builder->appendFormat("%s = %s.lookup(&%s)",
                          value, tblName, key);
}

void BccTarget::emitTableUpdate(Util::SourceCodeBuilder* builder, cstring tblName,
                                cstring key, cstring value) const {
    builder->appendFormat("%s.update(&%s, &%s);",
                          tblName, key, value);
}

void BccTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
    builder->append("#include <linux/bpf.h>\n");
}

void BccTarget::emitTableDecl(Util::SourceCodeBuilder* builder,
                              cstring tblName, bool isHash,
                              cstring keyType, cstring valueType, unsigned size) const {
    cstring kind = isHash ? "hash" : "array";
    builder->appendFormat("BPF_TABLE(\"%s\", %s, %s, %s, %d);",
                          kind, keyType, valueType, tblName, size);
    builder->newline();
}

void BccTarget::emitLicense(Util::SourceCodeBuilder*, cstring) const {}

void BccTarget::emitMain(Util::SourceCodeBuilder* builder,
                                   cstring functionName,
                                   cstring argName) const {
    builder->appendFormat("int %s(struct __sk_buff* %s)", functionName, argName);
}

////////////////////////////////////////////////////////////////

void XdpTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
    builder->append(
        "#define KBUILD_MODNAME \"xdptest\"\n"
        "#include <linux/bpf.h>\n"
        "#include \"bpf_helpers.h\"\n"
        "\n"
        "static __always_inline int ebpf_filter(struct xdp_md *skb);\n"
        "\n"
        "#define load_byte(data, b)  (*(u8 *)(data + (b)))\n"
        "#define load_half(data, b) __constant_ntohs(*(u16 *)(data + (b)))\n"
        "#define load_word(data, b) __constant_ntohl(*(u32 *)(data + (b)))\n"
                    );
}

void XdpTarget::emitMain(Util::SourceCodeBuilder* builder,
                                   cstring functionName,
                                   cstring argName) const {
    builder->appendFormat("SEC(\"prog\")\n"
                          "int %s(struct xdp_md* %s)", functionName, argName);
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

}  // namespace EBPF
