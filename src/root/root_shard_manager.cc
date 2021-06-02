#include "stdafx.h"
#include "root/root_shard_manager.h"

namespace tenon {

namespace root {

RootShardManager::RootShardManager() {
    std::fill(shards_, shards_ + network::kConsensusShardEndNetworkId, nullptr);
}

RootShardManager::~RootShardManager() {}

}  // namespace root

}  // namespace tenon
