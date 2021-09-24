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

    void SetTreeWithInvalidHeight(uint64_t max_height, uint64_t invalid_height) {
        HeightTreeLevel height_tree_level;
        for (uint64_t i = 0; i < max_height; ++i) {
            if (i == invalid_height) {
                continue;
            }

            height_tree_level.Set(i);
        }

//         height_tree_level.PrintTree();
        std::vector<uint64_t> invalid_heights;
        height_tree_level.GetMissingHeights(1, &invalid_heights, max_height - 1);
        ASSERT_TRUE(!invalid_heights.empty());
        ASSERT_EQ(invalid_heights[0], invalid_height);
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
    {
        std::vector<uint64_t> test_invalid_heidhts;
        uint64_t test_max_height = 4 * kLeafMaxHeightCount;
        for (uint64_t i = 0; i < 10; ++i) {
            srand(time(NULL));
            test_invalid_heidhts.push_back(rand() % test_max_height);
        }

        for (uint64_t i = 0; i < test_invalid_heidhts.size(); ++i) {
            SetTreeWithInvalidHeight(test_max_height, test_invalid_heidhts[i]);
        }
    }

    {
        std::vector<uint64_t> test_invalid_heidhts;
        uint64_t test_max_height = 2 * kLeafMaxHeightCount;
        for (uint64_t i = 0; i < 10; ++i) {
            srand(time(NULL));
            test_invalid_heidhts.push_back(rand() % test_max_height);
        }

        for (uint64_t i = 0; i < test_invalid_heidhts.size(); ++i) {
            SetTreeWithInvalidHeight(test_max_height, test_invalid_heidhts[i]);
        }
    }

    {
        std::vector<uint64_t> test_invalid_heidhts;
        uint64_t test_max_height = 1 * kLeafMaxHeightCount;
        for (uint64_t i = 0; i < 10; ++i) {
            srand(time(NULL));
            test_invalid_heidhts.push_back(rand() % test_max_height);
        }

        for (uint64_t i = 0; i < test_invalid_heidhts.size(); ++i) {
            SetTreeWithInvalidHeight(test_max_height, test_invalid_heidhts[i]);
        }
    }
}


}  // namespace test

}  // namespace sync

}  // namespace tenon
