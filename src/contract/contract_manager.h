#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"
#include "contract/contract_utils.h"
#include "contract/proto/contract.pb.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace contract {

class ContractManager {
public:
    static ContractManager* Instance();
    int Init();
//     int InitWithAttr(
//             const bft::protobuf::Block& block_item,
//             const bft::protobuf::TxInfo& tx_info,
//             db::DbWriteBach& db_batch);
//     int GetAttrWithKey(
//             const std::string& call_addr,
//             const std::string& key,
//             std::string& value);
//     virtual int Execute(bft::TxItemPtr& tx_item);
    virtual int call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res);

private:
    ContractManager();
    ~ContractManager();
    void HandleMessage(const transport::TransportMessagePtr& header);
//     void HandleGetContractAttrRequest(
//             transport::protobuf::Header& header,
//             protobuf::ContractMessage& block_msg);

    std::unordered_map<std::string, ContractInterfacePtr> contract_map_;
    std::mutex contract_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ContractManager);
};

}  // namespace contract

}  // namespace tenon
