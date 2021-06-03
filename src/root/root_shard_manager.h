#pragma once

#include <memory>

#include "network/network_utils.h"
#include "root/root_utils.h"
#include "root/shard_info.h"

namespace tenon {

namespace root {

class RootShardManager {
public:
    RootShardManager();
    ~RootShardManager();

private:
    ShardInfoPtr shards_[network::kConsensusShardEndNetworkId];

    DISALLOW_COPY_AND_ASSIGN(RootShardManager);
};

}  // namespace root

}  // namespace tenon
