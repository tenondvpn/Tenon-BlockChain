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
        std::cout << "invalid height: " << height << std::endl;
        LeafHeightTree leaf_height_tree(0, 0);
        for (uint64_t i = 0; i < kLeafMaxHeightCount; ++i) {
            if (i == height) {
                continue;
            }

            leaf_height_tree.Set(i);
        }

        std::vector<uint64_t> get_invalid_heights;
        leaf_height_tree.GetInvalidHeights(&get_invalid_heights);
        if (get_invalid_heights.empty()) {
            ASSERT_EQ(height > leaf_height_tree.max_height_);
            return;
        }

        ASSERT_TRUE(!get_invalid_heights.empty());
        ASSERT_EQ(get_invalid_heights[0], height);
    }

private:

};

TEST_F(TestLeafHeightTree, TestGetInvalidHeights) {
    LeafHeightTree leaf_height_tree(0, 0);
    std::vector<uint64_t> invalid_heights;
    for (uint32_t i = 0; i < 10; ++i) {
        invalid_heights.push_back(rand() % kLeafMaxHeightCount);
    }

    for (auto iter = invalid_heights.begin(); iter != invalid_heights.end(); ++iter) {
        TestGetInvalidHeight(*iter);
    }
}

TEST_F(TestLeafHeightTree, TestSetBranch) {
    LeafHeightTree leaf_height_tree(1, 0);
    for (uint64_t i = 0; i < kBranchMaxCount * 2; ++i) {
        leaf_height_tree.Set(i, 0xFFFFFFFFFFFFFFFFlu);
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
