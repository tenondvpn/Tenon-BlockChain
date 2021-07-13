#pragma once

#include "contract/contract_interface.h"
#include "db/db_unique_queue.h"
#include "common/tick.h"

namespace tenon {

namespace contract {

class Ripemd160 : public ContractInterface {
public:
    Ripemd160(const std::string& create_address);
    virtual ~Ripemd160();
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
        evmc_result* res);

private:
    uint64_t gas_cast_{ 3000llu };

    DISALLOW_COPY_AND_ASSIGN(Ripemd160);
};

}  // namespace contract

}  // namespace tenon
