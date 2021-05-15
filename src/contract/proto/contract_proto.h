#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "contract/proto/contract.pb.h"

namespace lego {

namespace contract {

class ContractProto {
public:
    static void CreateGetAttrRequest(
            const dht::NodePtr& local_node,
            const std::string& des_account,
            const std::string& call_addr,
            const std::string& key,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key());
        uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
        dht::DhtKeyManager dht_key(
                des_net_id,
                std::rand() % (std::numeric_limits<uint8_t>::max)());
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_type(common::kContractMessage);
        msg.set_hop_count(0);
        msg.set_client(local_node->client_mode);
        protobuf::ContractMessage contract_msg;
        auto attr_req = contract_msg.mutable_get_attr_req();
        attr_req->set_call_addr(call_addr);
        attr_req->set_attr_key(key);
        msg.set_data(contract_msg.SerializeAsString());
    }

    static void CreateGetAttrResponse(
            const dht::NodePtr& local_node,
            const transport::protobuf::Header& header,
            const std::string& contract_data,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key());
        msg.set_des_dht_key(header.src_dht_key());
        msg.set_priority(transport::kTransportPriorityLow);
        msg.set_id(header.id());
        msg.set_type(common::kContractMessage);
        msg.set_universal(header.universal());
        msg.set_from_ip(header.from_ip());
        msg.set_from_port(header.from_port());
        msg.set_transport_type(header.transport_type());
        if (header.has_debug()) {
            msg.set_debug(header.debug());
        }

        if (header.client()) {
            msg.set_client(header.client());
            msg.set_client_relayed(true);
            msg.set_client_proxy(header.client_proxy());
            msg.set_client_dht_key(header.client_dht_key());
            msg.set_client_handled(true);
        }
        msg.set_hop_count(0);
        msg.set_data(contract_data);
    }

private:
    ContractProto();
    ~ContractProto();
    DISALLOW_COPY_AND_ASSIGN(ContractProto);
};

}  // namespace contract

}  // namespace lego
