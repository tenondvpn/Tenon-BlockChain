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
}

LeafHeightTree::LeafHeightTree(const std::vector<uint64_t>& data) : data_(data) {}

LeafHeightTree::~LeafHeightTree() {}

LeafHeightTree::LeafHeightTree(const LeafHeightTree& src) {
    data_ = src.data_;
}

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
    assert(index < (data_.size() * 64));
    uint32_t vec_index = (index % (64 * data_.size())) / 64;
    uint32_t bit_index = (index % (64 * data_.size())) % 64;
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

LeafHeightTree& LeafHeightTree::operator=(const LeafHeightTree& src) {
    if (this == &src) {
        return *this;
    }

    data_ = src.data_;
    return *this;
}

bool LeafHeightTree::operator==(const LeafHeightTree& r) const {
    if (this == &r) {
        return true;
    }

    return data_ == r.data_;
}

uint32_t LeafHeightTree::GetRootIndex() {
    if (max_height_ == common::kInvalidUint64) {
        return 0;
    }

    uint32_t max_index = max_height_ - global_leaf_index_;
    uint32_t tmp_max_index = max_index / 64;
    if (tmp_max_index == 0) {
        return 0;
    }

    if (tmp_max_index == 1) {
        return kBranchMaxCount;
    }

    float tmp = log(tmp_max_index) / log(2);
    if (abs(tmp - (float(int(tmp)))) > (std::numeric_limits<float>::min)()) {
        tmp += 1;
    }

    uint32_t max_tmp = (uint32_t)pow(2.0, float(uint32_t(tmp)));
    return max_tmp + kBranchMaxCount - 2;
}

uint64_t LeafHeightTree::GetRoot() {
    return data_[GetRootIndex()];
}

void LeafHeightTree::ButtomUp(uint32_t vec_index) {
    if (vec_index % 2 != 0) {
        vec_index -= 1;
    }

    uint32_t parent_idx = kBranchMaxCount + vec_index / 2;
    while (parent_idx < kHeightLevelItemMaxCount) {
        data_[parent_idx] = data_[vec_index] & data_[vec_index + 1];
        vec_index = parent_idx;
        if (vec_index % 2 != 0) {
            vec_index -= 1;
        }

        parent_idx = kBranchMaxCount + vec_index / 2;
    }
}

}  // namespace sync

}  // namespace tenon
