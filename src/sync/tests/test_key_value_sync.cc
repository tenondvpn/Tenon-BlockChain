#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <unordered_set>
#include <vector>

#define private public
#include "sync/key_value_sync.h"
#include "init/network_init.h"
#include "init/init_utils.h"
#include "common/split.h"
#include "block/block_manager.h"
#include "network/network_utils.h"

namespace tenon {

namespace sync {

namespace test {

class TestKeyValueSync : public testing::Test {
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

TEST_F(TestKeyValueSync, TestSyncKeyValue) {

}

TEST_F(TestKeyValueSync, TestSyncHeight) {
    init::NetworkInit net_init;
    std::string params = "pl -U -1 031d29587f946b7e57533725856e3b2fc840ac8395311fea149642334629cd5757:127.0.0.1:9001,03a6f3b7a4a3b546d515bfa643fc4153b86464543a13ab5dd05ce6f095efb98d87:127.0.0.1:8001,031e886027cdf3e7c58b9e47e8aac3fe67c393a155d79a96a0572dd2163b4186f0:127.0.0.1:7001 -2 0315a968643f2ada9fd24f0ca92ae5e57d05226cfe7c58d959e510b27628c1cac0:127.0.0.1:7301,030d62d31adf3ccbc6283727e2f4493a9228ef80f113504518c7cae46931115138:127.0.0.1:7201,028aa5aec8f1cbcd995ffb0105b9c59fd76f29eaffe55521aad4f7a54e78f01e58:127.0.0.1:7101";
    common::Split<> params_split(params.c_str(), ' ', params.size());
    ASSERT_EQ(net_init.Init(params_split.cnt_, params_split.pt_), init::kInitSuccess);
    ASSERT_EQ(KeyValueSync::Instance()->AddSyncHeight(
        network::kRootCongressNetworkId, 0, 2, kSyncHigh), sync::kSyncSuccess);
}

}  // namespace test

}  // namespace sync

}  // namespace tenon
