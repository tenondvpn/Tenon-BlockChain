#pragma once

#include "contract/contract_interface.h"
#include "db/db_unique_queue.h"
#include "common/tick.h"

namespace lego {

namespace contract {

class Ecrecover : public ContractInterface {
public:
    Ecrecover(const std::string& create_address);
    virtual ~Ecrecover();
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
    uint64_t gas_cast_{ 3000llu };

    DISALLOW_COPY_AND_ASSIGN(Ecrecover);
};

}  // namespace contract

}  // namespace lego
