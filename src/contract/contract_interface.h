#pragma once

#include <map>
#include <memory>

#include "evmc/evmc.h"

#include "bft/tx_bft.h"
#include "db/db.h"
#include "contract/contract_utils.h"
#include "contract/call_parameters.h"

namespace tenon {

namespace contract {

class ContractInterface {
public:
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch) = 0;
    virtual int GetAttrWithKey(const std::string& key, std::string& value) = 0;
    // attr map can change, and save to block chain
    virtual int Execute(bft::TxItemPtr& tx_item) = 0;
    virtual int call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) = 0;

protected:
    ContractInterface(const std::string& create_address) : create_address_(create_address) {}
    virtual ~ContractInterface() {}

    std::string create_address_;

    DISALLOW_COPY_AND_ASSIGN(ContractInterface);
};

typedef std::shared_ptr<ContractInterface> ContractInterfacePtr;

}  // namespace contract

}  // namespace tenon
