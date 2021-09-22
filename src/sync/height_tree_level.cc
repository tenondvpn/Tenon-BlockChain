#include "sync/height_tree_level.h"
#include <unordered_map>
#include <cmath>
#include <cassert>

#include "common/utils.h"

namespace tenon {

namespace sync {

HeightTreeLevel::HeightTreeLevel() {}

HeightTreeLevel::~HeightTreeLevel() {}

int HeightTreeLevel::Set(uint64_t height) {
    if (max_height_ == common::kInvalidUint64) {
        max_height_ = height;
        max_level_ = GetMaxLevel();
    }

    if (height > max_height_) {
        max_height_ = height;
        max_level_ = GetMaxLevel();
    }

    uint64_t leaf_index = height / kLeafMaxHeightCount;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        TreeNodeMapPtr node_map_ptr = tree_level_[0];
        if (node_map_ptr == nullptr) {
            node_map_ptr = std::make_shared<TreeNodeMap>();
            tree_level_[0] = node_map_ptr;
        }

        LeafHeightTreePtr leaf_ptr = nullptr;
        auto iter = node_map_ptr->find(leaf_index);
        if (iter == node_map_ptr->end()) {
            leaf_ptr = std::make_shared<LeafHeightTree>(0, leaf_index);
            (*node_map_ptr)[leaf_index] = leaf_ptr;
//             std::cout << "create new leaf index: " << leaf_index << std::endl;
//             if (leaf_index != 0) {
//                 (*node_map_ptr)[leaf_index - 1]->PrintTree();
//             }
// 
//             std::cout << std::endl;
        } else {
            leaf_ptr = iter->second;
        }

        leaf_ptr->Set(height);
    }

    uint64_t child_idx = height / kLeafMaxHeightCount;
    for (uint32_t level = 0; level < max_level_; ++level) {
//         std::cout << "height: " << height << ", child_idx: " << child_idx << ", max_level_: " << max_level_ << std::endl;
        BottomUpWithBrantchLevel(level, child_idx);
        child_idx = child_idx / 2 / kBranchMaxCount;
    }

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

void HeightTreeLevel::BottomUpWithBrantchLevel(uint32_t level, uint64_t child_index) {
    uint32_t branch_index = child_index / 2 / kBranchMaxCount;
    ++level;
    std::lock_guard<std::mutex> guard(mutex_);
    uint64_t and_val = 0;
    uint64_t child_val1 = 0;
    uint64_t child_val2 = 0;
    {
        TreeNodeMapPtr node_map_ptr = tree_level_[level - 1];
        if (node_map_ptr == nullptr) {
            return;
        }

        LeafHeightTreePtr branch_ptr = nullptr;
        auto iter = node_map_ptr->find(child_index);
        if (iter == node_map_ptr->end()) {
            return;
        }

        child_val1 = iter->second->GetRoot();
        child_val2 = 0;
        if (child_index % 2 == 0) {
            iter = node_map_ptr->find(child_index + 1);
            if (iter != node_map_ptr->end()) {
                child_val2 = iter->second->GetRoot();
            }
        } else {
            iter = node_map_ptr->find(child_index - 1);
            if (iter != node_map_ptr->end()) {
                child_val2 = iter->second->GetRoot();
            }
        }

        and_val = child_val1 & child_val2;
    }
    
    {
        TreeNodeMapPtr node_map_ptr = tree_level_[level];
        if (node_map_ptr == nullptr) {
            node_map_ptr = std::make_shared<TreeNodeMap>();
            tree_level_[level] = node_map_ptr;
        }

        LeafHeightTreePtr branch_ptr = nullptr;
        auto iter = node_map_ptr->find(branch_index);
        if (iter == node_map_ptr->end()) {
            branch_ptr = std::make_shared<LeafHeightTree>(level, branch_index);
            (*node_map_ptr)[branch_index] = branch_ptr;
//             std::cout << "create new branch level: " << level << ", index: " << branch_index << std::endl;
        } else {
            branch_ptr = iter->second;
        }

        branch_ptr->Set(child_index, and_val);
//         std::cout << "branch_index: " << branch_index << ", set branch and value child_index: " << child_index << ", child1: " << child_val1 << ", child 2: " << child_val2 << ", and_val: " << and_val << ", level: " << level << std::endl;
//         branch_ptr->PrintTree();
//         std::cout << std::endl;
    }
}

uint32_t HeightTreeLevel::GetMaxLevel() {
    if (max_height_ < kLeafMaxHeightCount) {
        return 0;
    }

    uint32_t level = 0;
    uint64_t child_index = max_height_ / kLeafMaxHeightCount;
    while (true) {
        child_index = child_index / 2 / kBranchMaxCount;
        ++level;
        if (child_index == 0) {
            return level;
        }
    }

    return 0;
}

void HeightTreeLevel::PrintTree() {
    uint32_t level_vec_index = 1;
    std::cout << "all max_level_: " << max_level_ << std::endl;
    for (int32_t i = (int32_t)max_level_; i >= 0; --i) {
        auto level_map = tree_level_[i];
        if (i == max_level_) {
            auto iter = level_map->begin();
            iter->second->PrintTree();
            level_vec_index = iter->second->max_vec_index() + 1;
            if (level_vec_index >= kBranchMaxCount) {
                return;
            }

            continue;
        }

        level_vec_index *= 2;
        int32_t max_level = (int32_t)(log(kBranchMaxCount) / log(2));
        std::cout << "max_level: " << max_level << ", level_vec_index: " << level_vec_index << std::endl;
        for (int32_t level_idx = max_level; level_idx >= 0; --level_idx) {
            for (uint64_t vec_idx = 0; vec_idx < level_vec_index; ++vec_idx) {
                auto iter = level_map->find(vec_idx);
                assert(iter != level_map->end());
                iter->second->PrintLevel(level_idx);
            }

            std::cout << std::endl;
        }

        level_vec_index = kBranchMaxCount;
        std::cout << std::endl;
    }

}

};  // namespace sync

};  // namespace tenon
