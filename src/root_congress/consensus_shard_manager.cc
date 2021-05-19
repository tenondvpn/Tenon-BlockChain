#include "stdafx.h"
#include "root_congress/consensus_shard_manager.h"

namespace tenon {

namespace congress {

ConsensusShardManager::ConsensusShardManager() {
    std::fill(shards_, shards_ + network::kConsensusShardEndNetworkId, nullptr);
}

ConsensusShardManager::~ConsensusShardManager() {}

}  // namespace congress

}  // namespace tenon
