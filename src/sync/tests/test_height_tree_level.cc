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

private:

};

TEST_F(TestHeightTreeLevel, SetValid) {
    HeightTreeLevel height_tree_level;
    for (uint64_t i = 0; i < 1024; ++i) {
        height_tree_level.Set(i);
    }

    height_tree_level.PrintTree();
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
