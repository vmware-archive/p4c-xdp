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

#ifndef _XDPMODEL_H_
#define _XDPMODEL_H_

#include "backends/ebpf/ebpfModel.h"

namespace XDP {

struct XDP_Action_Model : public ::Model::Enum_Model {
    XDP_Action_Model() : Enum_Model("xdp_action"),
                         aborted("XDP_ABORTED"), drop("XDP_DROP"),
                         pass("XDP_PASS"), tx("XDP_TX") {}
    ::Model::Elem aborted;
    ::Model::Elem drop;
    ::Model::Elem pass;
    ::Model::Elem tx;
};

struct XDP_Switch_Model : public ::Model::Elem {
    XDP_Switch_Model() : Elem("xdp"),
                         parser("p"), swtch("s"), deparser("d") {}
    ::Model::Elem parser;
    ::Model::Elem swtch;
    ::Model::Elem deparser;
};

struct InputMetadataModel : public ::Model::Type_Model {
    InputMetadataModel() : ::Model::Type_Model("xdp_input"),
        inputPort("input_port"), inputPortType(IR::Type_Bits::get(32))
    {}

    ::Model::Elem inputPort;
    const IR::Type* inputPortType;
};

struct OutputMetadataModel : public ::Model::Type_Model {
    OutputMetadataModel() : ::Model::Type_Model("xdp_output"),
            outputPort("output_port"), outputPortType(IR::Type_Bits::get(32)),
                            output_action("output_action")
    {}

    ::Model::Elem outputPort;
    const IR::Type* outputPortType;
    ::Model::Elem output_action;
};

// Keep this in sync with xdp_model.p4
class XDPModel : public EBPF::EBPFModel {
 protected:
    XDPModel() : EBPF::EBPFModel(), xdp(), inputMetadataModel(), outputMetadataModel(),
                 ipv4_checksum("ebpf_ipv4_checksum"), bpf_event_output("bpf_event_output"),
                 bpf_ktime_get_ns("bpf_ktime_get_ns"), action_enum()
    {}

 public:
    static XDPModel instance;
    XDP_Switch_Model xdp;
    InputMetadataModel inputMetadataModel;
    OutputMetadataModel outputMetadataModel;
    ::Model::Extern_Model ipv4_checksum;
    ::Model::Extern_Model bpf_event_output;
    ::Model::Extern_Model bpf_ktime_get_ns;
    XDP_Action_Model      action_enum;
};

}  // namespace XDP

#endif /* _XDPMODEL_H_ */
