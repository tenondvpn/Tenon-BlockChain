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

    void SetTreeWithInvalidHeight(uint64_t height) {
        HeightTreeLevel height_tree_level;
        for (uint64_t i = 0; i < 1024; ++i) {
            if (i == height) {
                continue;
            }

            height_tree_level.Set(i);
        }

//         height_tree_level.PrintTree();
        std::vector<uint64_t> invalid_heights;
        height_tree_level.GetMissingHeights(1, &invalid_heights, 1023);
        ASSERT_TRUE(!invalid_heights.empty());
        std::cout << "invalid height: " << invalid_heights[0] << std::endl;
    }

private:

};

TEST_F(TestHeightTreeLevel, SetValid) {
    HeightTreeLevel height_tree_level;
    for (uint64_t i = 0; i < 1024; ++i) {
        height_tree_level.Set(i);
    }

    height_tree_level.PrintTree();
}

TEST_F(TestHeightTreeLevel, GetInvalidHeights) {
    HeightTreeLevel height_tree_level;
    for (uint64_t i = 0; i < 1; ++i) {
        SetTreeWithInvalidHeight(i);
    }
}


}  // namespace test

}  // namespace sync

}  // namespace tenon
