#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"

namespace tenon {

namespace contract {

class PayforVpn : public ContractInterface {
public:
    PayforVpn(const std::string& create_address) : ContractInterface(create_address) {}
    virtual ~PayforVpn() {}
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch);
    virtual int GetAttrWithKey(const std::string& key, std::string& value);
    virtual int Execute(bft::TxItemPtr tx_item);
    virtual int call(
            const CallParameters& param,
            uint64_t gas,
            const std::string& origin_address,
            evmc_result* res) {
        return kContractSuccess;
    }

private:
    struct PayInfo {
        uint64_t day_timestamp;
        uint64_t amount;
        uint64_t height;
        uint64_t end_day_timestamp;
    };
    std::unordered_map<std::string, PayInfo> payfor_all_map_;
    std::mutex payfor_all_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(PayforVpn);
};

}  // namespace contract

}  // namespace tenon
