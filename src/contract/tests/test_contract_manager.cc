#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "contract/contract_manager.h"
#include "contract/call_parameters.h"
#include "tvm/tvm_utils.h"
#include "common/encode.h"

namespace tenon {

namespace bignum {

namespace test {

class TestSnark : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestSnark, all) {
    contract::CallParameters params;
    params.gas = 100000000;
    params.apparent_value = 0;
    params.value = params.apparent_value;
    params.from = common::Encode::HexDecode("b8ce9ab6943e0eced004cde8e3bbed6568b2fa01");
    params.code_address = contract::kContractModexp;
    params.to = params.code_address;
    params.data = common::Encode::HexDecode(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "03"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    params.on_op = {};
    evmc_result call_result = {};
    evmc::result evmc_res{ call_result };
    evmc_result* raw_result = (evmc_result*)&evmc_res;
    if (contract::ContractManager::Instance()->call(
        params,
        10000000,
        "",
        raw_result) != contract::kContractNotExists) {
    }
}

}  // namespace test

}  // namespace bignum

}  // namespace tenon
