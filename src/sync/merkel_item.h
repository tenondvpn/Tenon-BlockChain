#pragma once

#include "sync/sync_utils.h"

namespace tenon {

namespace sync {


struct LeafMerkleItem {
    // all pool merge hash from 0 to common::kImmutablePoolSize + 1
    char hash[32];
    // all pool height pair with time block
    uint64_t pool_height_pair[kPoolHeightPairCount];
};

struct BranchesMerkleItem {
    char hash[32];
};

};  // namespace sync

};  // namespace tenon