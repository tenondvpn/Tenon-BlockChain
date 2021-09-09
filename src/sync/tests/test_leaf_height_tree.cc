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
    for (uint64_t i = 0; i < kEachHeightTreeMaxByteSize / 2; ++i) {
        leaf_height_tree.Set(i);
    }
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
