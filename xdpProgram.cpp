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

void XDPProgram::emit(EBPF::CodeBuilder *builder) {
    if (builder->target->name != "XDP") {
        ::error("This program must be compiled with --target xdp");
        return;
    }

    builder->target->emitIncludes(builder);
    emitPreamble(builder);
    emitTypes(builder);
    control->emitTables(builder);

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

    createLocalVariables(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::start.c_str());
    builder->newline();

    parser->emit(builder);
    emitPipeline(builder);

    builder->emitIndent();
    builder->append(endLabel);
    builder->appendLine(":");

    // TODO: write output port to a table

    builder->emitIndent();
    builder->appendFormat("if (%s.%s) return %s;",
                          getSwitch()->outputMeta->name.name,
                          XDPModel::instance.outputMetadataModel.drop.str(),
                          builder->target->dropReturnCode().c_str());
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("else return %s;", builder->target->forwardReturnCode().c_str());
    builder->newline();
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

void XDPProgram::createLocalVariables(EBPF::CodeBuilder* builder) {
    if (!switchTarget()) {
        EBPF::EBPFProgram::createLocalVariables(builder);
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
