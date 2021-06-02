#pragma once

#include "contract/contract_interface.h"
#include "db/db_unique_queue.h"
#include "common/tick.h"

namespace tenon {

namespace contract {

class ContractAltBn128G1Mul : public ContractInterface {
public:
    ContractAltBn128G1Mul(const std::string& create_address);
    virtual ~ContractAltBn128G1Mul();
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
    int64_t gas_cast_{ 6000ll };

    DISALLOW_COPY_AND_ASSIGN(ContractAltBn128G1Mul);
};

}  // namespace contract

}  // namespace tenon
