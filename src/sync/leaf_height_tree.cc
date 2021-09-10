#include "stdafx.h"
#include <cassert>
#include <cmath>

#include "sync/leaf_height_tree.h"
#include "sync/sync_utils.h"

namespace tenon {

namespace sync {

LeafHeightTree::LeafHeightTree(uint32_t level, uint64_t node_index) {
    if (level == 0) {
        global_leaf_index_ = node_index * kLeafMaxHeightCount;
    } else {
        global_leaf_index_ = node_index * kBranchMaxCount;
    }

    uint32_t data_cnt = kBranchMaxCount * 2;
    for (uint32_t i = 0; i < data_cnt; ++i) {
        data_.push_back(0ull);
    }

    InitVec();
}


LeafHeightTree::LeafHeightTree(const std::vector<uint64_t>& data) : data_(data) {
    InitVec();
}

void LeafHeightTree::InitVec() {
    uint32_t init_level_count = kBranchMaxCount;
    uint32_t init_rate = kBranchMaxCount;
    level_tree_index_vec_.push_back(std::make_pair(0, 0));
    for (uint32_t i = 0; i < 14; ++i) {
        level_tree_index_vec_.push_back(std::make_pair(init_level_count, init_rate));
        init_rate = init_rate / 2;
        init_level_count += init_rate;
    }
}

LeafHeightTree::~LeafHeightTree() {}


void LeafHeightTree::Set(uint64_t index) {
    if (index < global_leaf_index_ || index >= global_leaf_index_ + kEachHeightTreeMaxByteSize) {
        assert(false);
        return;
    }

    if (max_height_ == common::kInvalidUint64) {
        max_height_ = index;
    }

    if (index > max_height_) {
        max_height_ = index;
    }

    index = index - global_leaf_index_;
    assert(index < kLeafMaxHeightCount);
    uint32_t vec_index = index / 64;
    uint32_t bit_index = index % 64;
    data_[vec_index] |= (uint64_t)((uint64_t)(1) << bit_index);
    ButtomUp(vec_index);
}

bool LeafHeightTree::Valid(uint64_t index) {
    if (index < global_leaf_index_ || index >= global_leaf_index_ + kEachHeightTreeMaxByteSize) {
        assert(false);
        return false;
    }

    index = index - global_leaf_index_;
    assert(index < (data_.size() * 64));
    uint32_t vec_index = (index % (64 * data_.size())) / 64;
    uint32_t bit_index = (index % (64 * data_.size())) % 64;
    if ((data_[vec_index] & ((uint64_t)((uint64_t)(1) << bit_index))) == 0ull) {
        return false;
    }

    return true;
}

uint32_t LeafHeightTree::GetRootIndex() {
    uint32_t max_level = GetAlignMaxLevel();
    return level_tree_index_vec_[max_level].first;
}

uint32_t LeafHeightTree::GetAlignMaxLevel() {
    if (max_height_ == common::kInvalidUint64) {
        return 0;
    }

    uint32_t max_index = max_height_ - global_leaf_index_;
    uint32_t tmp_max_index = max_index / 64;
    if (tmp_max_index == 0) {
        return 0;
    }

    if (tmp_max_index == 1) {
        return 1;
    }

    if (tmp_max_index % 2 == 0) {
        tmp_max_index += 1;
    }

    float tmp = log(tmp_max_index) / log(2);
    if (tmp - float(int(tmp)) > (std::numeric_limits<float>::min)()) {
        tmp += 1;
    }

    return tmp;
}

uint64_t LeafHeightTree::GetRoot() {
    return data_[GetRootIndex()];
}

void LeafHeightTree::ButtomUp(uint32_t vec_index) {
    uint32_t max_level = GetAlignMaxLevel();
    uint32_t src_vec_index = vec_index;
    for (uint32_t i = 0; i < max_level; ++i) {
        if (vec_index % 2 != 0) {
            vec_index -= 1;
        }

        uint32_t parent_index = level_tree_index_vec_[i + 1].first + src_vec_index / 2;
        data_[parent_index] = data_[vec_index] & data_[vec_index + 1];
        vec_index = parent_index;
        src_vec_index /= 2;
    }
}

void LeafHeightTree::PrintTreeFromRoot() {
    int32_t max_root_index = GetRootIndex();
    int32_t max_level = GetAlignMaxLevel();
    std::cout << data_[max_root_index] << std::endl;
    uint32_t level_rate = 1;
    for (int32_t i = max_level - 1; i >= 0; --i) {
        level_rate *= 2;
        uint32_t end_idx = level_tree_index_vec_[i].first + level_rate;
        std::cout << level_rate << " ----- ";
        for (uint32_t level_idx = level_tree_index_vec_[i].first; level_idx < end_idx; ++level_idx) {
            std::cout << data_[level_idx] << " ";
        }

        std::cout << std::endl;
    }
}

void LeafHeightTree::GetInvalidHeights(std::vector<uint64_t>* height_vec) {
    int32_t parent_index = GetRootIndex();
    if (data_[parent_index] == kLevelNodeValidHeights) {
        return;
    }

    int32_t max_level = GetAlignMaxLevel();
    uint32_t level_rate = 1;
    int32_t parent_level_idx = 0;
    for (int32_t i = max_level - 1; i >= 0; --i) {
        int32_t left_idx = level_tree_index_vec_[i].first + parent_level_idx * 2;
        int32_t right_idx = level_tree_index_vec_[i].first + parent_level_idx * 2 + 1;
        if (data_[left_idx] != kLevelNodeValidHeights) {
            parent_level_idx = left_idx;
        } else {
            parent_level_idx = right_idx;
        }
    }

    std::cout << "parent_level_idx: " << parent_level_idx << std::endl;
}

}  // namespace sync

}  // namespace tenon
