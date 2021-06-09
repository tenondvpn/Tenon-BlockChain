#include "bft/bft_utils.h"

#include "election/member_manager.h"
#include "network/network_utils.h"

namespace tenon {

namespace bft {

std::string StatusToString(uint32_t status) {
    switch (status) {
    case kBftInit:
        return "bft_init";
    case kBftPrepare:
        return "bft_prepare";
    case kBftPreCommit:
        return "bft_precommit";
    case kBftCommit:
        return "bft_commit";
    case kBftCommited:
        return "bft_success";
    default:
        return "unknown";
    }
}

// hash128(gid + from + to + amount + type + attrs(k:v))
std::string GetTxMessageHash(const protobuf::TxInfo& tx_info) {
    std::string message = tx_info.gid() + "-" +
        tx_info.from() + "-" +
        tx_info.to() + "-" +
        std::to_string(tx_info.amount()) + "-" +
        std::to_string(tx_info.type()) + "-";
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        message += tx_info.attr(i).key() + tx_info.attr(i).value();
    }

    for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
        message += tx_info.transfers(i).from() +
            tx_info.transfers(i).to() +
            std::to_string(tx_info.transfers(i).amount());
    }

    for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
        message += tx_info.storages(i).key() +
            tx_info.storages(i).value();
    }

    return common::Hash::Hash128(message);
}

// prehash + network_id + height + random + elect version + txes's hash
std::string GetBlockHash(const protobuf::Block& block) {
    std::string message = block.prehash() + "-" +
        std::to_string(block.network_id()) + "-" +
        std::to_string(block.height()) + "-" +
        std::to_string(block.consistency_random()) + "-" +
        std::to_string(block.elect_ver()) + "-";
    for (int32_t i = 0; i < block.tx_list_size(); ++i) {
        message += GetTxMessageHash(block.tx_list(i));
    }

    return common::Hash::Sha256(message);
}

uint32_t NewAccountGetNetworkId(const std::string& addr) {
    return static_cast<uint32_t>((common::Hash::Hash64(addr) *
        vss::VssManager::Instance()->EpochRandom()) %
        common::GlobalInfo::Instance()->consensus_shard_count()) +
        network::kConsensusShardBeginNetworkId;
}

std::string GetUniversalGid(bool to, const std::string& gid) {
    return std::to_string(common::GlobalInfo::Instance()->network_id()) +
        (to ? std::string("_t_") : std::string("_")) +
        gid;
}

bool ThisNodeIsLeader() {
    int32_t pool_mod_num = elect::MemberManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
    return pool_mod_num >= 0;
}

int32_t GetLeaderPoolIndex() {
    return elect::MemberManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
}

bool IsRootSingleBlockTx(uint32_t tx_type) {
    if (tx_type == common::kConsensusRootElectRoot ||
            tx_type == common::kConsensusRootElectShard ||
            tx_type == common::kConsensusRootTimeBlock ||
            tx_type == common::kConsensusRootVssBlock) {
        return true;
    }

    return false;
}

}  // namespace bft

}  //namespace tenon
