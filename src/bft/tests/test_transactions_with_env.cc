#include <iostream>
#include <thread>

#include <gtest/gtest.h>
#include "common/log.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/config.h"
#include "common/random.h"
#include "init/command.h"
#include "ip/ip_with_country.h"
#include "db/db.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

namespace tenon {

namespace client {

namespace test {

class TestRandomTransaction : public testing::Test {
public:
    static void SetUpTestCase() {
        system("rm -rf ./core.* ./test_db");
        tenon::common::Config conf;
        ASSERT_TRUE(conf.Init("./conf/tenon.conf"));
        std::string local_ip;
        conf.Get("tenon", "local_ip", local_ip);
        uint16_t local_port;
        conf.Get("tenon", "local_port", local_port);
        std::string bootstrap;
        conf.Get("tenon", "bootstrap", bootstrap);
        bool show_cmd;
        conf.Get("tenon", "show_cmd", show_cmd);
        bool run_tx = false;
        conf.Get("tenon", "run_tx", run_tx);
        tenon::common::SignalRegister();
        ASSERT_EQ(tenon::ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf"), tenon::ip::kIpSuccess);
        auto int_res = tenon::client::VpnClient::Instance()->Init(
            local_ip,
            2,
            bootstrap,
            "./conf/",
            "3.0.0",
            "");
        ASSERT_TRUE(int_res != "ERROR");
    }
};

TEST_F(TestRandomTransaction, TransactionAccountsExists) {
    ASSERT_TRUE(true);
}

}  // namespace test

}  // namespace client

}  // namespace tenon