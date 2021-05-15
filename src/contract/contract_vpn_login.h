#pragma once

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnLogin : public ContractInterface {
public:
    VpnLogin(const std::string& create_address) : ContractInterface(create_address) {}
    virtual ~VpnLogin() {}
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch);
    virtual int GetAttrWithKey(const std::string& key, std::string& value);
    virtual int Execute(bft::TxItemPtr& tx_item);
    virtual int call(
            const CallParameters& param,
            uint64_t gas,
            const std::string& origin_address,
            evmc_result* res) {
        return kContractSuccess;
    }

protected:
    DISALLOW_COPY_AND_ASSIGN(VpnLogin);
};

}  // namespace contract

}  // namespace lego
