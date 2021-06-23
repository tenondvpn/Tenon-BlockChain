#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "common/min_heap.h"
#include "common/random.h"

namespace tenon {

namespace common {

namespace test {

class TestMinHeap : public testing::Test {
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

TEST_F(TestMinHeap, TestMax) {
    LimitHeap<uint64_t, true> test_min_heap(true, 1024);
    uint64_t max_data = 0;
    for (uint64_t i = 0; i < 1000; ++i) {
        auto data = common::Random::RandomUint16();
        test_min_heap.push(data);
        if (max_data < data) {
            max_data = data;
        }
    }

    ASSERT_EQ(max_data, test_min_heap.top());
    while (!test_min_heap.empty()) {
        std::cout << test_min_heap.top() << " ";
        test_min_heap.pop();
    }

    std::cout << std::endl;
}

TEST_F(TestMinHeap, TestMin) {
    LimitHeap<uint64_t, false> test_min_heap(true, 1024);
    uint64_t max_data = 999999999;
    for (uint64_t i = 0; i < 1000; ++i) {
        auto data = common::Random::RandomUint16();
        test_min_heap.push(data);
        if (max_data > data) {
            max_data = data;
        }
    }


    ASSERT_EQ(max_data, test_min_heap.top());
    while (!test_min_heap.empty()) {
        std::cout << test_min_heap.top() << " ";
        test_min_heap.pop();
    }

    std::cout << std::endl;
}

}  // namespace test

}  // namespace common

}  // namespace tenon
