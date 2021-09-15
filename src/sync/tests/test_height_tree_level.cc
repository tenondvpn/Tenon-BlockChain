#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <unordered_set>
#include <vector>

#define private public
#include "sync/height_tree_level.h"
#include "sync/sync_utils.h"

namespace tenon {

namespace sync {

namespace test {

class TestHeightTreeLevel : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    void TestGetInvalidHeight(uint64_t height) {
        LeafHeightTree leaf_height_tree(0, 0);
        for (uint64_t i = 0; i < kLeafMaxHeightCount; ++i) {
            if (i == height) {
                continue;
            }

            leaf_height_tree.Set(i);
        }

        std::vector<uint64_t> get_invalid_heights;
        leaf_height_tree.GetInvalidHeights(&get_invalid_heights);
        ASSERT_EQ(get_invalid_heights[0], height);
    }

private:

};

TEST_F(TestHeightTreeLevel, SetValid) {
    HeightTreeLevel height_tree_level;
    for (uint64_t i = 0; i < 1024; ++i) {
        height_tree_level.Set(i);
    }

    height_tree_level.PrintTree();
//     std::cout << height_tree_level.max_height_ << ":" << height_tree_level.max_level_ << std::endl;
//     uint32_t level_vec_index = 1;
//     for (int32_t i = (int32_t)height_tree_level.max_level_; i >= 0; --i) {
//         auto level_map = height_tree_level.tree_level_[i];
//         for (uint64_t vec_idx = 0; vec_idx < level_vec_index; ++vec_idx) {
//             auto iter = level_map->find(vec_idx);
//             ASSERT_TRUE(iter != level_map->end());
//         }
//     }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
