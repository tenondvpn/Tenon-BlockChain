#include "stdafx.h"
#include <cassert>

#include "sync/leaf_height_tree.h"
#include "sync/sync_utils.h"

namespace tenon {

namespace sync {

LeafHeightTree::LeafHeightTree(uint64_t global_leaf_index) {
    global_leaf_index_ = global_leaf_index;
    uint32_t data_cnt = kEachHeightTreeMaxByteSize / 64;
    for (uint32_t i = 0; i < data_cnt; ++i) {
        data_.push_back(0ull);
    }
    assert(!data_.empty());
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

void LeafHeightTree::ButtomUp(uint32_t vec_index) {
    uint32_t init_level_count = kEachHeightTreeMaxByteSize / 2 / 64;
    for (int32_t level = 0; level < kHeightTreeLeafMaxLevel; ++level) {
        uint32_t parent_index = init_level_count + vec_index / 2;
        if (vec_index % 2 == 0) {
            data_[parent_index] = data_[vec_index] & data_[vec_index + 1];
        } else {
            data_[parent_index] = data_[vec_index - 1] & data_[vec_index];
        }

        init_level_count += init_level_count / 2;
        vec_index = parent_index;
    }
}

}  // namespace sync

}  // namespace tenon
