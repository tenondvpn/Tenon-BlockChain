#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>

#include "dht/dht_key.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread.h"
#include "transport/transport_utils.h"
#define private public
#include "network/network_utils.h"
#include "bls/bls_sign.h"
#include "bls/bls_dkg.h"

namespace tenon {

namespace bls {

namespace test {

class TestBls : public testing::Test {
public:
    static void SetUpTestCase() {    
//         transport_ = std::make_shared<tenon::transport::UdpTransport>(
//                 "127.0.0.1",
//                 9701,
//                 1024 * 1024,
//                 1024 * 1024);
//         if (transport_->Init() != tenon::transport::kTransportSuccess) {
//             return;
//         }
//         transport_->Start(false);
//         tenon::transport::MultiThreadHandler::Instance()->Init(transport_, nullptr);
    }

    static void TearDownTestCase() {
//         transport_->Stop();
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

//     static tenon::transport::TransportPtr transport_;
};

// tenon::transport::TransportPtr TestBls::transport_ = nullptr;

TEST_F(TestBls, BinarySearch) {
    // t = 7, n = 10
    static const uint32_t t = 7;
    static const uint32_t n = 10;

    BlsDkg dkg[n];
    elect::MembersPtr members = std::make_shared<elect::Members>();
    std::vector<std::string> pri_vec;
    for (uint32_t i = 0; i < n; ++i) {
        pri_vec.push_back(common::Random::RandomString(32));
    }

    for (uint32_t i = 0; i < pri_vec.size(); ++i) {
        security::PrivateKey prikey(pri_vec[i]);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        security::CommitSecret secret;
        members->push_back(std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1));
    }

    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].OnNewElectionBlock(1, members);
    }

}

}  // namespace test

}  // namespace bls

}  // namespace tenon
