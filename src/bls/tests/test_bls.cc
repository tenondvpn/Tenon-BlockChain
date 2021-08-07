#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "dht/dht_key.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread/multi_thread.h"
#include "transport/transport_utils.h"
#define private public
#include "bls/bls_sign.h"
#include "bls/dkg.h"

namespace tenon {

namespace bls {

namespace test {

class TestBls : public testing::Test {
public:
    static void SetUpTestCase() {    
        tenon::transport::MultiThreadHandler::Instance()->Init();
        transport_ = std::make_shared<tenon::transport::UdpTransport>(
                "127.0.0.1",
                9701,
                1024 * 1024,
                1024 * 1024);
        if (transport_->Init() != tenon::transport::kTransportSuccess) {
            ERROR("init udp transport failed!");
            return;
        }
        transport_->Start(false);
    }

    static void TearDownTestCase() {
        transport_->Stop();
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    static tenon::transport::TransportPtr transport_;
};

tenon::transport::TransportPtr TestBls::transport_ = nullptr;

TEST_F(TestBls, BinarySearch) {
    // t = 7, n = 10
    static const uint32_t t = 7;
    static const uint32_t n = 10;

    Dkg dkg[10];

}

}  // namespace test

}  // namespace bls

}  // namespace tenon