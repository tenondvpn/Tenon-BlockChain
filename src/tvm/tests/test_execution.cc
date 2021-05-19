#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#include "common/encode.h"
#define private public
#include "tvm/execution.h"
#include "tvm/tvm_utils.h"
#include "tvm/tenon_host.h"

namespace tenon {

namespace tvm {

namespace test {

class TestExecution : public testing::Test {
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

TEST_F(TestExecution, All) {
    tvm::Execution exec;
    std::string contract_address;
    std::string input;
    std::string from;
    std::string to;
    std::string origin_address;
    uint64_t value;
    uint64_t gas_limit;
    uint32_t depth = 0;
    bool is_create = false;
    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tvm::TenonHost tenon_host;
    exec.execute(
        contract_address,
        input,
        from,
        to,
        origin_address,
        value,
        gas_limit,
        depth,
        is_create,
        tenon_host,
        &res);
}

}  // namespace test

}  // namespace tvm

}  // namespace tenon
