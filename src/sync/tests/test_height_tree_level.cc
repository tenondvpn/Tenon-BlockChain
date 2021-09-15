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

TEST_F(TestHeightTreeLevel, TestGetInvalidHeights) {
    HeightTreeLevel height_tree_level;
    for (uint64_t i = 0; i < 1024 * 1024; ++i) {
        height_tree_level.Set(i);
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
