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
        uint64_t fts_value = rand() % (std::numeric_limits<uint64_t>::max)();
        std::string* new_data = new std::string(
            common::Encode::HexEncode(common::Random::RandomString(32)) +
            "_" + std::to_string(fts_value));
        test_vec.push_back(new_data);
        fts_tree.AppendFtsNode(fts_value, new_data);
    }

    fts_tree.CreateFtsTree();
    std::string* data = (std::string*)fts_tree.GetOneNode(1000);
    std::cout << *data << std::endl;
}

}  // namespace test

}  // namespace common

}  // namespace tenon
