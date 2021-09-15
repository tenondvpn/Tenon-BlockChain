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

        std::vector<uint64_t> get_invalid_heights;
        leaf_height_tree.GetInvalidHeights(&get_invalid_heights);
        ASSERT_EQ(get_invalid_heights[0], height);
    }

private:

};

TEST_F(TestLeafHeightTree, TestGetInvalidHeights) {
    LeafHeightTree leaf_height_tree(0, 0);
    std::unordered_set<uint64_t> invalid_heights = {
        23,
        1024,
        346545,
        1024 * 156,
        1024 * 1021,
    };

    for (uint32_t i = 0; i < 10; ++i) {
        invalid_heights.insert(rand() % (1024 * 1024));
    }

    for (auto iter = invalid_heights.begin(); iter != invalid_heights.end(); ++iter) {
        TestGetInvalidHeight(*iter);
    }
}

TEST_F(TestLeafHeightTree, TestSetBranch) {
    LeafHeightTree leaf_height_tree(1, 0);
    for (uint64_t i = 0; i < 16384; ++i) {
        leaf_height_tree.Set(i, 0xFFFFFFFFFFFFFFFFlu);
        leaf_height_tree.PrintBranchTreeFromRoot();
        std::cout << std::endl;
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
