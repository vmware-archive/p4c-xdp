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
#include "frontends/p4/methodInstance.h"

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

    codeGen = new EBPF::ControlBodyTranslator(this, builder);
    codeGen->substitute(headers, parserHeaders);

    scanConstants();
    return ::errorCount() == 0;
}

//////////////////////////////////////////////////////////////////////////

namespace {

class OutHeaderSize final : public EBPF::CodeGenInspector {
    P4::ReferenceMap*  refMap;
    P4::TypeMap*       typeMap;
    const XDPProgram*  program;
    EBPF::CodeBuilder* builder;

    std::map<const IR::Parameter*, const IR::Parameter*> substitution;

    bool illegal(const IR::Statement* statement)
    { ::error("%1%: not supported in deparser", statement); return false; }

 public:
    OutHeaderSize(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                  const XDPProgram* program, EBPF::CodeBuilder* builder):
            EBPF::CodeGenInspector(builder, typeMap), refMap(refMap), typeMap(typeMap),
            program(program), builder(builder) {
        CHECK_NULL(refMap); CHECK_NULL(typeMap); CHECK_NULL(program); CHECK_NULL(builder);
        setName("OutHeaderSize"); }
    bool preorder(const IR::PathExpression* expression) override {
        auto decl = refMap->getDeclaration(expression->path, true);
        auto param = decl->getNode()->to<IR::Parameter>();
        if (param != nullptr) {
            auto subst = ::get(substitution, param);
            if (subst != nullptr) {
                builder->append(subst->name);
                return false;
            }
        }
        builder->append(expression->path->name);
        return false;
    }
    bool preorder(const IR::SwitchStatement* statement) override
    { return illegal(statement); }
    bool preorder(const IR::IfStatement* statement) override
    { return illegal(statement); }
    bool preorder(const IR::AssignmentStatement* statement) override
    { return illegal(statement); }
    bool preorder(const IR::ReturnStatement* statement) override
    { return illegal(statement); }
    bool preorder(const IR::ExitStatement* statement) override
    { return illegal(statement); }
    bool preorder(const IR::MethodCallStatement* statement) override {
        auto &p4lib = P4::P4CoreLibrary::instance;

        auto mi = P4::MethodInstance::resolve(statement->methodCall, refMap, typeMap);
        auto method = mi->to<P4::ExternMethod>();
        if (method == nullptr)
            return illegal(statement);

        auto declType = method->originalExternType;
        if (declType->name.name != p4lib.packetOut.name ||
            method->method->name.name != p4lib.packetOut.emit.name ||
            method->expr->arguments->size() != 1) {
            return illegal(statement);
        }

        auto h = method->expr->arguments->at(0);
        auto type = typeMap->getType(h);
        auto ht = type->to<IR::Type_Header>();
        if (ht == nullptr) {
            ::error("Cannot emit a non-header type %1%", h);
            return false;
        }
        unsigned width = ht->width_bits();

        builder->append("if (");
        visit(h);
        builder->append(".ebpf_valid) ");
        builder->appendFormat("%s += %d;", program->outHeaderLengthVar.c_str(), width);
        return false;
    }

    void substitute(const IR::Parameter* p, const IR::Parameter* with)
    { substitution.emplace(p, with); }
};

}  // namespace

XDPDeparser::XDPDeparser(const XDPProgram* program, const IR::ControlBlock* block,
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

    codeGen = new EBPF::ControlBodyTranslator(this, builder);
    codeGen->substitute(headers, parserHeaders);

    return true;
}

void XDPDeparser::emit() {
    OutHeaderSize ohs(program->refMap, program->typeMap,
                      static_cast<const XDPProgram*>(program), builder);
    ohs.substitute(headers, parserHeaders);

    builder->emitIndent();
    (void)controlBlock->container->body->apply(ohs);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("// bpf_xdp_adjust_head(%s, BYTES(%s) - %s);",
                          program->model.CPacketName.str(),
                          program->offsetVar.c_str(),
                          getProgram()->outHeaderLengthVar.c_str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          program->packetStartVar,
                          builder->target->dataOffset(program->model.CPacketName.str()));
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("%s = %s;",
                          program->packetEndVar,
                          builder->target->dataEnd(program->model.CPacketName.str()));
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("%s = 0;", program->offsetVar.c_str());
    builder->newline();

    EBPF::EBPFControl::emit();
}

}  // namespace XDP
