#include <unordered_map>

#include "common/utils.h"
#include "sync/height_tree_level.h"

namespace tenon {

namespace sync {

HeightTreeLevel::HeightTreeLevel() {}

HeightTreeLevel::~HeightTreeLevel() {}

int HeightTreeLevel::SetHeight(uint64_t height) {
    if (max_height_ == common::kInvalidUint64) {
        max_height_ = height;
    }

    if (height > max_height_) {
        max_height_ = height;
    }

    uint64_t leaf_index = height / kLeafMaxHeightCount;
    uint32_t height_index = height % kLeafMaxHeightCount;
    std::lock_guard<std::mutex> guard(mutex_);
    TreeNodeMapPtr node_map_ptr = tree_level_[0];
    if (node_map_ptr == nullptr) {
        node_map_ptr = std::make_shared<TreeNodeMap>();
        tree_level_[leaf_index] = node_map_ptr;
    }

    LeafHeightTreePtr leaf_ptr = nullptr;
    auto iter = node_map_ptr->find(leaf_index);
    if (iter == node_map_ptr->end()) {
        leaf_ptr = std::make_shared<LeafHeightTree>(0, leaf_index);
    } else {
        leaf_ptr = iter->second;
    }

    leaf_ptr->Set(height);
    return kSyncSuccess;
}

int HeightTreeLevel::GetMissingHeights(uint32_t count, std::vector<uint64_t>* heights) {
    return kSyncSuccess;
}

void HeightTreeLevel::GetHeightMaxLevel(uint64_t height, uint32_t* level, uint64_t* index) {
    *level = 0;
    uint32_t leaf_count = height / kLeafMaxHeightCount;
    if (leaf_count == 0) {
        return;
    }

    leaf_count += 1;
    while (leaf_count > 0) {
        leaf_count /= kBranchMaxCount;
        leaf_count += 1;
        ++(*level);
    }
}

};  // namespace sync

};  // namespace tenon
