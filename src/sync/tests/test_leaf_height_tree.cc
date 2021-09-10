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
        std::cout << "max_height_: " << leaf_height_tree.max_height_ << ", level: " << leaf_height_tree.GetAlignMaxLevel() << std::endl;
    }

    for (uint64_t i = 0; i < kMaxHeight; ++i) {
        leaf_height_tree.Set(i);
        leaf_height_tree.PrintTreeFromRoot();
        std::cout << std::endl;
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
