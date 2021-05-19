#pragma once

#include "contract/contract_interface.h"
#include "db/db_unique_queue.h"
#include "common/tick.h"

namespace tenon {

namespace contract {

class VpnMining : public ContractInterface {
public:
    VpnMining(const std::string& create_address) : ContractInterface(create_address) {
        TickPayForMiningNode();
    }

    virtual ~VpnMining() {}
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

private:
    void CreateVpnMiningBft(
            const std::string& account_id,
            uint64_t amount,
            const std::string& attr_key);
    void PayForMiningNode();
    void TickPayForMiningNode();
    int HandleConsensusVpnMining(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch);
    int HandleConsensusVpnMiningPayForNode(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch);

    db::UniqueQueue mining_unique_queue_{ "vpn_mining_cq", 100000 };
    common::Tick mining_pay_for_node_tick_;

    DISALLOW_COPY_AND_ASSIGN(VpnMining);
};

}  // namespace contract

}  // namespace tenon
