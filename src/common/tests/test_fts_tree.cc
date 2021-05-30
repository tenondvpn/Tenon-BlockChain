#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <limits>

#define private public
#include "common/fts_tree.h"
#include "common/random.h"
#include "common/encode.h"

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
    const uint32_t kTestCount = 3u;
    FtsTree fts_tree;
    std::vector<std::string*> test_vec;
    for (uint32_t i = 0; i < kTestCount; ++i) {
        uint64_t fts_value = i;
        std::string* new_data = new std::string(
            common::Encode::HexEncode(common::Random::RandomString(32)) +
            "_" + std::to_string(fts_value));
        test_vec.push_back(new_data);
        fts_tree.AppendFtsNode(fts_value, new_data);
    }

    fts_tree.CreateFtsTree();
    for (auto iter = fts_tree.fts_nodes_.rbegin(); iter != fts_tree.fts_nodes_.rend(); ++iter) {
        std::cout << iter->fts_value << std::endl;
    }

    std::string* data = (std::string*)fts_tree.GetOneNode(1000);
    std::cout << *data << std::endl;
    for (auto iter = test_vec.begin(); iter != test_vec.end(); ++iter) {
        delete *iter;
    }
}

}  // namespace test

}  // namespace common

}  // namespace tenon
