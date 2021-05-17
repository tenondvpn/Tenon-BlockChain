#include "bft/bft_utils.h"

#include "bft/member_manager.h"
#include "network/network_utils.h"

namespace lego {

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
        message += block.tx_list(i).tx_hash();
    }

    return common::Hash::Sha256(message);
}

// prehash + network_id + height + random + elect version + txes's hash
std::string GetBlockHash(
        const protobuf::Block& block,
        const std::string& txes_hash) {
    std::string message = block.prehash() + "-" +
        std::to_string(block.network_id()) + "-" +
        std::to_string(block.height()) + "-" +
        std::to_string(block.consistency_random()) + "-" +
        std::to_string(block.elect_ver()) + "-" +
        txes_hash;
    return common::Hash::Sha256(message);
}

uint32_t NewAccountGetNetworkId(const std::string& addr) {
    return static_cast<uint32_t>((common::Hash::Hash64(addr) *
        crand::ConsistencyRandom::Instance()->Random()) %
        common::GlobalInfo::Instance()->consensus_shard_count()) +
        network::kConsensusShardBeginNetworkId;
}

std::string GetUniversalGid(bool to, const std::string& gid) {
    return std::to_string(common::GlobalInfo::Instance()->network_id()) +
        (to ? std::string("_t_") : std::string("_")) +
        gid;
}

bool ThisNodeIsLeader() {
    return MemberManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id(),
        crand::ConsistencyRandom::Instance()->Random());
}

}  // namespace bft

}  //namespace lego
