#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "client/vpn_client.h"

namespace tenon {

namespace client {

namespace test {

class TestBaseTransaction : public testing::Test {
public:
    static void SetUpTestCase() {
        auto res = client::VpnClient::Instance()->Init(
            "127.0.0.1",
            0,
            "id:127.0.0.1:9001,id:127.0.0.1:7001,id:127.0.0.1:8001,id:127.0.0.1:7101,id:127.0.0.1:7301,id:127.0.0.1:7201",
            "./test",
            "ver",
            "e154d5e5fc28b7f715c01ca64058be7466141dc6744c89cbcc5284e228c01269");
        std::cout << "res: " << res << std::endl;
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

private:

};

TEST_F(TestBaseTransaction, GetAccountInfos) {
    int64_t balance = client::VpnClient::Instance()->GetBalance();
    std::cout << "get balance: " << balance << std::endl;
}

TEST_F(TestBaseTransaction, TransExistsAccount) {

}

}  // namespace test

}  // namespace client

}  // namespace tenon
