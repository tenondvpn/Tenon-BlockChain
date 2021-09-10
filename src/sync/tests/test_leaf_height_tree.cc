#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "sync/leaf_height_tree.h"
#include "sync/sync_utils.h"

namespace tenon {

namespace sync {

namespace test {

class TestLeafHeightTree : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

private:

};

TEST_F(TestLeafHeightTree, All) {
    LeafHeightTree leaf_height_tree(0, 0);
    const uint64_t kMaxHeight = 64 * 8;
    for (uint64_t i = 0; i < kMaxHeight; ++i) {
        leaf_height_tree.max_height_ = i;
        std::cout << "max_height_: " << max_height_ << ", level: " << leaf_height_tree.GetAlignMaxLevel() << std::endl;
    }

    exit(0);
    for (uint64_t i = 0; i < kMaxHeight; ++i) {
        leaf_height_tree.Set(i);
        uint32_t root_idx = leaf_height_tree.GetRootIndex();
        std::string res_str;
        for (uint32_t idx = 0; idx < i / 64 + 1; ++idx) {
            res_str += std::to_string(leaf_height_tree.data_[idx]) + ", ";
        }

        res_str += " ----- ";
        for (uint32_t r_idx = 16384; r_idx <= root_idx; ++r_idx) {
            res_str += std::to_string(leaf_height_tree.data_[r_idx]) + ", ";
        }

        std::cout << "route index: " << leaf_height_tree.GetRootIndex() << ":" << leaf_height_tree.GetRoot() << ", branchs: " << res_str << std::endl;
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
