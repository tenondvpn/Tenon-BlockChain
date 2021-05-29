#pragma once

#include "contract/contract_interface.h"
#include "db/db_unique_queue.h"
#include "common/tick.h"

namespace tenon {

namespace contract {

class ContractaltBn128PairingProduct : public ContractInterface {
public:
    ContractaltBn128PairingProduct(const std::string& create_address);
    virtual ~ContractaltBn128PairingProduct();
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
        evmc_result* res);

private:

    DISALLOW_COPY_AND_ASSIGN(ContractaltBn128PairingProduct);
};

}  // namespace contract

}  // namespace tenon
