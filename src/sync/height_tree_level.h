#pragma once

#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "sync/leaf_height_tree.h"
#include "sync/sync_utils.h"

namespace tenon {

namespace sync {

class HeightTreeLevel {
public:
    HeightTreeLevel();
    ~HeightTreeLevel();
    int SetHeight(uint64_t height);
    int GetMissingHeights(uint32_t count, std::vector<uint64_t>* heights);

private:
    typedef std::unordered_map<uint64_t, LeafHeightTreePtr> TreeNodeMap;
    typedef std::shared_ptr<TreeNodeMap> TreeNodeMapPtr;

    void GetHeightMaxLevel(uint64_t height, uint32_t* level, uint64_t* index);

    static const uint32_t kMaxLevelCount = 64u;

    // Max:  2 ^ (64 - 1) * 1M * 1M block height, 
    TreeNodeMapPtr tree_level_[kMaxLevelCount];
    uint64_t max_height_{ common::kInvalidUint64 };
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(HeightTreeLevel);
};

};  // namespace sync

};  // namespace tenon
