#include "stdafx.h"
#include "client/trans_client.h"

#include "common/encode.h"
#include "transport/proto/transport.pb.h"
#include "security/security.h"
#include "network/universal.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "client/proto/client_proto.h"

namespace tenon {

namespace client {

TransactionClient* TransactionClient::Instance() {
    static TransactionClient ins;
    return &ins;
}

int TransactionClient::Transaction(
        const std::string& to,
        uint64_t amount,
        const std::string& contract_addr,
        const std::map<std::string, std::string>& attrs,
        uint32_t type,
        std::string& tx_gid) {
    if (common::GlobalInfo::Instance()->consensus_shard_net_id() == common::kInvalidUint32) {
        CLIENT_ERROR("Transaction error, consensus shard network id invalid.");
        return kClientError;
    }

    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return kClientError;
    }

    tx_gid = common::CreateGID(security::Security::Instance()->str_pubkey());
    ClientProto::CreateTransactionWithAttr(
            uni_dht->local_node(),
            tx_gid,
            to,
            amount,
            type,
            contract_addr,
            attrs,
            msg);
    network::Route::Instance()->Send(msg);
    return kClientSuccess;
}

}  // namespace client

}  // namespace tenon
