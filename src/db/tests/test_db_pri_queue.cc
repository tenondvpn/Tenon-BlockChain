#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "bzlib.h"

#define private public
#include "db/db.h"
#include "db/db_pri_queue.h"

namespace tenon {

namespace db {

namespace test {

class TestDbPriQueue : public testing::Test {
public:
    static void SetUpTestCase() {    
        Db::Instance()->Init("/tmp/rocksdb_simple_example");
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

struct AccountBalance {
    int64_t balance;
    char account_id[64];
};

bool operator<(AccountBalance& lhs, AccountBalance& rhs) {
    return lhs.balance < rhs.balance;
}

TEST_F(TestDbPriQueue, All) {
    db::DbWriteBach write_batch;
    db::DbPriQueue<uint64_t, 32> acc_pri_q_{ "ten_test2" };
    std::cout << "init: " << std::endl;
    for (uint32_t i = 0; i < acc_pri_q_.size_; ++i) {
        std::cout << acc_pri_q_.data_[i] << std::endl;
    }

    std::cout << std::endl;
    for (uint32_t i = 0; i < 10240; ++i) {
        std::string acc_id = std::to_string(i);
        acc_pri_q_.push(i, write_batch);
        auto st = db::Db::Instance()->Put(write_batch);
        ASSERT_TRUE(st.ok());
        write_batch.Clear();
    }

    std::cout << std::endl;
    std::cout << "use mem data: " << std::endl;
    auto min_heap = acc_pri_q_.GetMemData();
    while (!min_heap.empty()) {
        std::cout <<  min_heap.top() << std::endl;
        min_heap.pop();
    }

//     std::cout << std::endl;
//     std::cout << "finish: " << std::endl;
//     while (!acc_pri_q_.empty()) {
//         std::cout << acc_pri_q_.top()->account_id << ":" << acc_pri_q_.top()->balance << std::endl;
//         acc_pri_q_.pop(write_batch);
//         auto st = db::Db::Instance()->Put(write_batch);
//         ASSERT_TRUE(st.ok());
//         write_batch.Clear();
// 
//     }
//     std::cout << std::endl;
}

}  // namespace test

}  // namespace db

}  // namespace tenon
