#pragma once

#include <vector>
#include <memory>

#include "common/utils.h"
#include "common/bitmap.h"

namespace tenon {

namespace sync {

class LeafHeightTree {
public:
    LeafHeightTree(uint32_t level, uint64_t node_index);
    LeafHeightTree(const std::vector<uint64_t>& data);
    ~LeafHeightTree();
    void Set(uint64_t bit_index);
    bool Valid(uint64_t bit_index);
    void GetInvalidHeights(std::vector<uint64_t>* height_vec);

    const std::vector<uint64_t>& data() const {
        return data_;
    }

    void clear() {
        for (uint32_t i = 0; i < data_.size(); ++i) {
            data_[i] = 0;
        }
    }

    uint64_t GetRoot();

private:
    void ButtomUp(uint32_t vec_index);
    uint32_t GetRootIndex();
    uint32_t GetAlignMaxLevel();
    void PrintTreeFromRoot();
    void InitVec();

    std::vector<uint64_t> data_;
    uint64_t global_leaf_index_{ common::kInvalidUint64 };
    uint64_t max_height_{ common::kInvalidUint64 };
    uint32_t prev_root_index_{ common::kInvalidUint32 };
    std::vector<std::pair<uint32_t, uint32_t>> level_tree_index_vec_;
};

typedef std::shared_ptr<LeafHeightTree> LeafHeightTreePtr;

};  // namespace sync

};  // namespace tenon