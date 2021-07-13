#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"

namespace tenon {

namespace contract {

class VpnClientLogin : public ContractInterface {
public:
    VpnClientLogin(const std::string& create_address) : ContractInterface(create_address) {}
    virtual ~VpnClientLogin() {}
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
    std::unordered_map<std::string, std::map<uint32_t, uint32_t>> client_login_map_;
    std::mutex client_login_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(VpnClientLogin);
};

}  // namespace contract

}  // namespace tenon
