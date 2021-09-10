#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <unordered_set>
#include <vector>

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

    void TestGetInvalidHeight(uint64_t height) {
        LeafHeightTree leaf_height_tree(0, 0);
        for (uint64_t i = 0; i < kLeafMaxHeightCount; ++i) {
            if (i == height) {
                continue;
            }

            leaf_height_tree.Set(i);
        }

        leaf_height_tree.PrintTreeFromRoot();
        std::cout << std::endl;
        std::vector<uint64_t> get_invalid_heights;
        leaf_height_tree.GetInvalidHeights(&get_invalid_heights);
        ASSERT_EQ(get_invalid_heights[0], height);
    }

private:

};

TEST_F(TestLeafHeightTree, All) {
    LeafHeightTree leaf_height_tree(0, 0);
    for (uint64_t i = 0; i < kLeafMaxHeightCount; ++i) {
        leaf_height_tree.Set(i);
    }

    leaf_height_tree.PrintTreeFromRoot();
    std::cout << std::endl;
}

TEST_F(TestLeafHeightTree, TestGetInvalidHeights) {
    LeafHeightTree leaf_height_tree(0, 0);
    std::unordered_set<uint64_t> invalid_heights = {
        23,
        65,
        78,
        1024,
        2098,
        78901,
        346545,
        1024 * 56,
        1024 * 156,
        1024 * 256,
        1024 * 456,
        1024 * 656,
        1024 * 756,
        1024 * 1021,
    };

    for (auto iter = invalid_heights.begin(); iter != invalid_heights.end(); ++iter) {
        TestGetInvalidHeight(*iter);
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
