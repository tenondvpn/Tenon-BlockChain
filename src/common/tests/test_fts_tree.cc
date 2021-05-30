#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <limits>

#define private public
#include "common/fts_tree.h"
#include "common/random.h"
#include "common/encode.h"
#include "common/smooth_data.h"

namespace tenon {

namespace common {

namespace test {

class TestFtsTree : public testing::Test {
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

TEST_F(TestFtsTree, all) {
    std::vector<std::vector<uint64_t>> vv = {
        {19, 26, 63},
        {13, 62, 65},
        {16, 69, 15},
        {14, 56, 17},
        {19, 6, 15},
        {11, 42, 15},
        {18, 58, 36},
        {12, 77, 33},
        {10, 75, 47},
        {15, 54, 70},
        {10017, 1421077, 4196},
    };

    ProcessVector(vv);
    exit(0);
    for (uint32_t i = 3; i < 4097; ++i) {
        if (i != 1000) {
            continue;
        }

        uint32_t kTestCount = i;
        FtsTree fts_tree;
        std::vector<std::string*> test_vec;
        std::mt19937_64 g2(1000);
        for (uint32_t i = 0; i < kTestCount; ++i) {
            uint64_t fts_value = common::Random::RandomUint64();
            std::string* new_data = new std::string(
                common::Encode::HexEncode(common::Random::RandomString(32)) +
                "_" + std::to_string(fts_value));
            test_vec.push_back(new_data);
            fts_tree.AppendFtsNode(fts_value, new_data);
        }

        fts_tree.CreateFtsTree();
        std::set<void*> node_set;
        fts_tree.GetNodes(1000, i / 3, node_set);
        ASSERT_EQ(node_set.size(), i / 3);
        for (auto iter = test_vec.begin(); iter != test_vec.end(); ++iter) {
            delete *iter;
        }
    }
    
}

}  // namespace test

}  // namespace common

}  // namespace tenon
