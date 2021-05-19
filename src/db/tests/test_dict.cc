#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#define private public
#include "db/dict.h"

namespace tenon {

namespace db {

namespace test {

class TestDict : public testing::Test {
public:
    static void SetUpTestCase() {    
        Db::Instance()->Init("./test_db");
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestDict, All) {
    db::DbWriteBach write_batch;
    auto put_st = Dict::Instance()->Hset("key", "field", "value", write_batch);
    ASSERT_TRUE(put_st);
    auto st = db::Db::Instance()->Put(write_batch);
    ASSERT_TRUE(st.ok());
    std::string value;
    auto get_st = Dict::Instance()->Hget("key", "field", &value);
    ASSERT_TRUE(get_st);
    ASSERT_EQ(value, "value");
    auto delete_st = Dict::Instance()->Hdel("key", "field");
    ASSERT_TRUE(delete_st);
    auto get_st2 = Dict::Instance()->Hget("key", "field", &value);
    ASSERT_FALSE(get_st2);
}

}  // namespace test

}  // namespace db

}  // namespace tenon
