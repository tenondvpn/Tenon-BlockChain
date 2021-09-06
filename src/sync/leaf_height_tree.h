#pragma once

#include "common/utils.h"
#include "common/bitmap.h"

namespace tenon {

namespace sync {

class LeafHeightTree {
public:
    LeafHeightTree(uint64_t global_leaf_index);
    LeafHeightTree(const std::vector<uint64_t>& data);
    LeafHeightTree(const LeafHeightTree& src);
    ~LeafHeightTree();
    void Set(uint64_t bit_index);
    bool Valid(uint64_t bit_index);
    LeafHeightTree& operator=(const LeafHeightTree& src);
    bool operator==(const LeafHeightTree& r) const;

    const std::vector<uint64_t>& data() const {
        return data_;
    }

    void clear() {
        for (uint32_t i = 0; i < data_.size(); ++i) {
            data_[i] = 0;
        }
    }

private:
    void ButtomUp(uint32_t vec_index);

    std::vector<uint64_t> data_;
    uint64_t global_leaf_index_{ common::kInvalidUint64 };
};

};  // namespace sync

};  // namespace tenon