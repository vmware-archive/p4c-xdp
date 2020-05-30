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

#include "backends/ebpf/ebpfType.h"
#include "backends/ebpf/ebpfControl.h"
#include "backends/ebpf/ebpfParser.h"
#include "backends/ebpf/ebpfTable.h"
#include "frontends/p4/coreLibrary.h"
#include "xdpProgram.h"
#include "xdpControl.h"

namespace XDP {

bool XDPProgram::build() {
    auto pack = toplevel->getMain();
    unsigned paramCount = pack->getConstructorParameters()->size();

    cstring parserParamName;
    if (paramCount == 2) {
        parserParamName = model.filter.parser.name;
    } else if (paramCount == 3) {
        parserParamName = xdp_model.xdp.parser.name;
    } else {
        ::error("%1%: Expected 2 or 3 package parameters", pack);
    }

    auto pb = pack->getParameterValue(parserParamName)
            ->to<IR::ParserBlock>();
    BUG_CHECK(pb != nullptr, "No parser block found");
    parser = new EBPF::EBPFParser(this, pb, typeMap);
    bool success = parser->build();
    if (!success)
        return success;

    if (paramCount == 2) {
        cstring controlParamName = model.filter.filter.name;
        auto cb = pack->getParameterValue(controlParamName)
                ->to<IR::ControlBlock>();
        BUG_CHECK(cb != nullptr, "No control block found");
        control = new EBPF::EBPFControl(this, cb, parser->headers);
        success = control->build();
        if (!success)
            return success;
    } else {
        cstring controlParamName = xdp_model.xdp.swtch.name;
        auto cb = pack->getParameterValue(controlParamName)
                ->to<IR::ControlBlock>();
        BUG_CHECK(cb != nullptr, "No control block found");
        control = new XDPSwitch(this, cb, parser->headers);
        success = control->build();
        if (!success)
            return success;
    }

    if (paramCount == 3) {
        auto db = pack->getParameterValue(xdp_model.xdp.deparser.name)
                ->to<IR::ControlBlock>();
        BUG_CHECK(db != nullptr, "No deparser block found");
        deparser = new XDPDeparser(this, db, parser->headers);
        success = deparser->build();
        if (!success)
            return success;
    }

    return true;
}

void XDPProgram::emitTypes(EBPF::CodeBuilder* builder) {
    for (auto d : program->objects) {
        if (!d->is<IR::Type>()) continue;

        if (d->is<IR::IContainer>() || d->is<IR::Type_Extern>() ||
            d->is<IR::Type_Parser>() || d->is<IR::Type_Control>() ||
            d->is<IR::Type_Typedef>() || d->is<IR::Type_Error>())
            continue;

        if (d->is<IR::Type_Enum>()) {
            if (d->to<IR::Type_Enum>()->name == XDPModel::instance.action_enum.name)
                continue;
        }

        auto type = EBPF::EBPFTypeFactory::instance->create(d->to<IR::Type>());
        if (type == nullptr)
            continue;
        type->emit(builder);
        builder->newline();
    }
}

void XDPProgram::emitC(EBPF::CodeBuilder* builder, cstring headerFile) {
    emitGeneratedComment(builder);

    if (!switchTarget()) {
        EBPF::EBPFProgram::emitC(builder, headerFile);
        return;
    }

    if (builder->target->name != "XDP") {
        ::error("This program must be compiled with --target xdp");
        return;
    }

    builder->appendFormat("#include \"%s\"", headerFile);
    builder->newline();
    builder->target->emitIncludes(builder);
    emitPreamble(builder);
    control->emitTableInstances(builder);

    builder->appendLine(
        "inline u16 ebpf_ipv4_checksum(u8 version, u8 ihl, u8 diffserv,\n"
        "                  u16 totalLen, u16 identification, u8 flags,\n"
        "                  u16 fragOffset, u8 ttl, u8 protocol,\n"
        "                  u32 srcAddr, u32 dstAddr) {\n"
        "    u32 checksum = __bpf_htons(((u16)version << 12) | ((u16)ihl << 8) | (u16)diffserv);\n"
        "    checksum += __bpf_htons(totalLen);\n"
        "    checksum += __bpf_htons(identification);\n"
        "    checksum += __bpf_htons(((u16)flags << 13) | fragOffset);\n"
        "    checksum += __bpf_htons(((u16)ttl << 8) | (u16)protocol);\n"
        "    srcAddr = __bpf_ntohl(srcAddr);\n"
        "    dstAddr = __bpf_ntohl(dstAddr);\n"
        "    checksum += (srcAddr >> 16) + (u16)srcAddr;\n"
        "    checksum += (dstAddr >> 16) + (u16)dstAddr;\n"
        "    // Fields in 'struct Headers' are host byte order.\n"
        "    // Deparser converts to network byte-order\n"
        "    return bpf_ntohs(~((checksum & 0xFFFF) + (checksum >> 16)));\n"
        "}");

    builder->appendLine(
                "inline u16 csum16_add(u16 csum, u16 addend) {\n"
                "    u16 res = csum;\n"
                "    res += addend;\n"
                "    return (res + (res < addend));\n"
                "}\n"
                "inline u16 csum16_sub(u16 csum, u16 addend) {\n"
                "    return csum16_add(csum, ~addend);\n"
                "}\n"
                "inline u16 csum_replace2(u16 csum, u16 old, u16 new) {\n"
                "    return (~csum16_add(csum16_sub(~csum, old), new));\n"
        "}\n");

    builder->appendLine(
        "inline u16 csum_fold(u32 csum) {\n"
        "    u32 r = csum << 16 | csum >> 16;\n"
        "    csum = ~csum;\n"
        "    csum -= r;\n"
        "    return (u16)(csum >> 16);\n"
        "}\n"
        "inline u32 csum_unfold(u16 csum) {\n"
        "    return (u32)csum;\n"
        "}\n"
                "inline u32 csum32_add(u32 csum, u32 addend) {\n"
                "    u32 res = csum;\n"
                "    res += addend;\n"
                "    return (res + (res < addend));\n"
                "}\n"
                "inline u32 csum32_sub(u32 csum, u32 addend) {\n"
                "    return csum32_add(csum, ~addend);\n"
                "}\n"
                "inline u16 csum_replace4(u16 csum, u32 from, u32 to) {\n"
        "    u32 tmp = csum32_sub(~csum_unfold(csum), from);\n"
                "    return csum_fold(csum32_add(tmp, to));\n"
        "}\n");

    builder->appendLine(
        "struct bpf_elf_map SEC(\"maps\") perf_event = {\n"
        "   .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,\n"
        "   .size_key = sizeof(u32),\n"
        "   .size_value = sizeof(u32),\n"
        "   .pinning = 1,\n"
        "   .max_elem = 2,\n"
        "};\n"
        "#define BPF_PERF_EVENT_OUTPUT() do {\\\n"
        "    int pktsize = (int)(skb->data_end - skb->data);\\\n"
        "    bpf_perf_event_output(skb, &perf_event, ((u64)pktsize << 32), &pktsize, 4);\\\n"
        "} while(0);\n");

    builder->appendLine(
        "#define BPF_KTIME_GET_NS() ({\\\n"
        "   u32 ___ts = (u32)bpf_ktime_get_ns(); ___ts; })\\\n");

    // The table used for forwarding: we write the output in it
    // TODO: this should use target->emitTableDecl().
    // We can't do it today because it has a different map type PERCPU_ARRAY
    builder->emitIndent();
    builder->appendFormat("struct bpf_elf_map SEC(\"maps\") %s = ", outTableName.c_str());
    builder->blockStart();
    builder->emitIndent();
    builder->append(".type = ");
    builder->appendLine("BPF_MAP_TYPE_PERCPU_ARRAY,");

    builder->emitIndent();
    builder->append(".size_key = sizeof(u32),");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".size_value = sizeof(u32),");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".pinning = 2, /* PIN_OBJECT_NS */");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat(".max_elem = 1 /* No multicast support */");
    builder->newline();

    builder->blockEnd(false);
    builder->endOfStatement(true);

    builder->newline();
    builder->emitIndent();
    builder->target->emitCodeSection(builder, functionName);
    builder->emitIndent();
    builder->target->emitMain(builder, functionName, model.CPacketName.str());
    builder->blockStart();

    emitHeaderInstances(builder);
    builder->append(" = ");
    parser->headerType->emitInitializer(builder);
    builder->endOfStatement(true);

    emitLocalVariables(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::start.c_str());
    builder->newline();

    parser->emit(builder);
    emitPipeline(builder);

    builder->emitIndent();
    builder->append(endLabel);
    builder->appendLine(":");

    // write output port to a table
    builder->emitIndent();
    builder->appendFormat("bpf_map_update_elem(&%s, &%s, &%s.%s, BPF_ANY)",
                          outTableName.c_str(), zeroKey.c_str(),
                          getSwitch()->outputMeta->name.name,
                          XDPModel::instance.outputMetadataModel.outputPort.str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("return %s.%s",
                          getSwitch()->outputMeta->name.name,
                          XDPModel::instance.outputMetadataModel.output_action.str());
    builder->endOfStatement(true);
    builder->blockEnd(true);  // end of function

    builder->target->emitLicense(builder, license);
}

void XDPProgram::emitPipeline(EBPF::CodeBuilder* builder) {
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->newline();

    builder->emitIndent();
    builder->blockStart();
    control->emit(builder);
    builder->blockEnd(true);

    if (switchTarget()) {
        builder->emitIndent();
        builder->append("/* deparser */");
        builder->newline();
        builder->emitIndent();
        builder->blockStart();
        deparser->emit(builder);
        builder->blockEnd(true);
    }
}

void XDPProgram::emitLocalVariables(EBPF::CodeBuilder* builder) {
    if (!switchTarget()) {
        EBPF::EBPFProgram::emitLocalVariables(builder);
        return;
    }

    builder->emitIndent();
    builder->appendFormat("unsigned %s = 0;", offsetVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("enum %s %s = %s;", errorEnum, errorVar,
                          P4::P4CoreLibrary::instance.noError.str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetStartVar, builder->target->dataOffset(model.CPacketName.str()));
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetEndVar, builder->target->dataEnd(model.CPacketName.str()));
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", zeroKey);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u8 %s = 0;", byteVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", outHeaderLengthVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct %s %s;", xdp_model.outputMetadataModel.name,
                          getSwitch()->outputMeta->name.name);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("/* TODO: this should be initialized by the environment. HOW? */");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct %s %s;", xdp_model.inputMetadataModel.name,
                          getSwitch()->inputMeta->name.name);
    builder->newline();
}

XDPSwitch* XDPProgram::getSwitch() const {
    return dynamic_cast<XDPSwitch*>(control);
}

}  // namespace XDP
