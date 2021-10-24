#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>

#include "common/random.h"
#include "common/hash.h"
#include "dht/dht_key.h"
#include "db/db.h"
#include "election/elect_dht.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/secp256k1.h"
#include "security/crypto_utils.h"
#include "security/schnorr.h"
#include "security/ecdh_create_key.h"
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
        db::Db::Instance()->Init("./test_db");
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

    static void SetGloableInfo(const std::string& private_key, uint32_t network_id) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        security::Schnorr::Instance()->set_prikey(std::make_shared<security::PrivateKey>(prikey));
        common::GlobalInfo::Instance()->set_id(id);
        common::GlobalInfo::Instance()->set_consensus_shard_count(1);
        common::GlobalInfo::Instance()->set_network_id(network_id);
        security::EcdhCreateKey::Instance()->Init();
        JoinNetwork(network::kRootCongressNetworkId);
        JoinNetwork(network::kUniversalNetworkId);
        JoinNetwork(network::kConsensusShardBeginNetworkId);
    }

    static void JoinNetwork(uint32_t network_id) {
        network::DhtManager::Instance()->UnRegisterDht(network_id);
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id);
        dht::DhtKeyManager dht_key(
            network_id,
            common::GlobalInfo::Instance()->country(),
            common::GlobalInfo::Instance()->id());
        dht::NodePtr local_node = std::make_shared<dht::Node>(
            common::GlobalInfo::Instance()->id(),
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            false,
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            security::Schnorr::Instance()->str_pubkey(),
            common::GlobalInfo::Instance()->node_tag());
        local_node->first_node = true;
        transport::TransportPtr transport;
        auto dht = std::make_shared<elect::ElectDht>(transport, local_node);
        dht->Init(nullptr, nullptr);
        auto base_dht = std::dynamic_pointer_cast<dht::BaseDht>(dht);
        network::DhtManager::Instance()->RegisterDht(network_id, base_dht);
        network::UniversalManager::Instance()->RegisterUniversal(network_id, base_dht);
    }
//     static tenon::transport::TransportPtr transport_;
};

// tenon::transport::TransportPtr TestBls::transport_ = nullptr;

TEST_F(TestBls, AllSuccess) {
    // t = 7, n = 10
    static const uint32_t t = 7;
    static const uint32_t n = 10;

    BlsDkg dkg[n] = {
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
    };
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = "127.0.0.1";
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].OnNewElectionBlock(1, members);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].local_member_index_ = i;
        dkg[i].BroadcastVerfify();
        verify_brd_msgs.push_back(dkg[i].ver_brd_msg_);
        dkg[i].DumpContribution();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                verify_brd_msgs[i]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // swap sec key
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].SwapSecKey();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // sign and verify
    auto hash = common::Hash::Sha256("hello world");
    std::vector<libff::alt_bn128_G1> all_signs;
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
        ASSERT_TRUE(dkg[i].finished_);
    }

    std::vector<size_t> idx_vec(t);
    for (size_t i = 0; i < t; ++i) {
        BlsSign bls_sign;
        libff::alt_bn128_G1 sign;
        bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &sign);
        ASSERT_EQ(
            bls_sign.Verify(t, n, sign, hash, dkg[i].local_publick_key_),
            kBlsSuccess);
        all_signs.push_back(sign);
        idx_vec[i] = i + 1;
    }

    crypto::Bls bls_instance = crypto::Bls(t, n);
    auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
        all_signs,
        lagrange_coeffs);

    for (uint32_t i = 0; i < n; ++i) {
        BlsSign bls_sign;
        EXPECT_EQ(
            bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
            kBlsSuccess);
    }
}

TEST_F(TestBls, FinishWithMissingNodesNoVerify) {
    // t = 7, n = 10
    static uint32_t t = 7;
    static uint32_t n = 10;

    BlsDkg dkg[10] = {
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
    };
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = "127.0.0.1";
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].OnNewElectionBlock(1, members);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].local_member_index_ = i;
        dkg[i].BroadcastVerfify();
        verify_brd_msgs.push_back(dkg[i].ver_brd_msg_);
        dkg[i].DumpContribution();
    }

    static const uint32_t kInvalidNodeIndex = 5;
    static const uint32_t kInvalidSwapNodeIndex = 3;
    static const uint32_t kInvalidSwapNodeIndex2 = 4;
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                verify_brd_msgs[i]);
            if (i == kInvalidNodeIndex) {
                continue;
            }

            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // swap sec key
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].SwapSecKey();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            if (i == kInvalidSwapNodeIndex && j == kInvalidSwapNodeIndex2) {
                continue;
            }

            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // sign and verify
    auto hash = common::Hash::Sha256("hello world");
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
        if (i != kInvalidNodeIndex) {
            ASSERT_TRUE(dkg[i].finished_);
        }
    }

    std::vector<libff::alt_bn128_G1> all_signs;
    std::vector<size_t> idx_vec(t);
    for (size_t i = 0; i < n; ++i) {
        if (i == kInvalidNodeIndex || i == kInvalidSwapNodeIndex || i == kInvalidSwapNodeIndex2) {
            continue;
        }

        BlsSign bls_sign;
        libff::alt_bn128_G1 sign;
        bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &sign);
        ASSERT_EQ(
            bls_sign.Verify(t, n, sign, hash, dkg[i].local_publick_key_),
            kBlsSuccess);
        all_signs.push_back(sign);
        idx_vec[all_signs.size() - 1] = i + 1;
        if (all_signs.size() >= t) {
            break;
        }
    }

    crypto::Bls bls_instance = crypto::Bls(t, n);
    auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
        all_signs,
        lagrange_coeffs);
    for (uint32_t i = 0; i < n; ++i) {
        if (i == kInvalidNodeIndex) {
            continue;
        }

        BlsSign bls_sign;
        EXPECT_EQ(
            bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
            kBlsSuccess);
    }
}

TEST_F(TestBls, FinishWithMissingNodesNoVerify5) {
    // t = 7, n = 10
    static uint32_t t = 4;
    static uint32_t n = 5;

    BlsDkg dkg[5] = {
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
    };
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = "127.0.0.1";
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].OnNewElectionBlock(1, members);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].local_member_index_ = i;
        dkg[i].BroadcastVerfify();
        verify_brd_msgs.push_back(dkg[i].ver_brd_msg_);
        dkg[i].DumpContribution();
    }

    static const uint32_t kInvalidNodeIndex = 3;
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                verify_brd_msgs[i]);
            if (i == kInvalidNodeIndex) {
                continue;
            }

            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // swap sec key
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].SwapSecKey();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // sign and verify
    auto hash = common::Hash::Sha256("hello world");
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
        if (i != kInvalidNodeIndex) {
            ASSERT_TRUE(dkg[i].finished_);
        }
    }

    std::vector<libff::alt_bn128_G1> all_signs;
    std::vector<size_t> idx_vec(t);
    for (size_t i = 0; i < n; ++i) {
        if (i == kInvalidNodeIndex) {
            continue;
        }

        BlsSign bls_sign;
        libff::alt_bn128_G1 sign;
        bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &sign);
        ASSERT_EQ(
            bls_sign.Verify(t, n, sign, hash, dkg[i].local_publick_key_),
            kBlsSuccess);
        all_signs.push_back(sign);
        idx_vec[all_signs.size() - 1] = i + 1;
        if (all_signs.size() >= t) {
            break;
        }
    }

    crypto::Bls bls_instance = crypto::Bls(t, n);
    auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
        all_signs,
        lagrange_coeffs);
    for (uint32_t i = 0; i < n; ++i) {
        if (i == kInvalidNodeIndex) {
            continue;
        }

        BlsSign bls_sign;
        EXPECT_EQ(
            bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
            kBlsSuccess);
    }
}

TEST_F(TestBls, ThreeRatioFailFine) {
    // t = 7, n = 10
    static const uint32_t t = 7;
    static const uint32_t n = 10;

    BlsDkg dkg[n] = {
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
    };
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = "127.0.0.1";
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].OnNewElectionBlock(1, members);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].local_member_index_ = i;
        dkg[i].BroadcastVerfify();
        verify_brd_msgs.push_back(dkg[i].ver_brd_msg_);
        dkg[i].DumpContribution();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                verify_brd_msgs[i]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // swap sec key
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].SwapSecKey();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].all_secret_key_contribution_[i][3] = libff::alt_bn128_Fr::zero();
        dkg[i].all_secret_key_contribution_[i][6] = libff::alt_bn128_Fr::zero();
        dkg[i].all_secret_key_contribution_[i][9] = libff::alt_bn128_Fr::zero();
        dkg[i].invalid_node_map_[3] = 9;
        dkg[i].invalid_node_map_[6] = 9;
        dkg[i].invalid_node_map_[9] = 9;
    }

    // sign and verify
    auto hash = common::Hash::Sha256("hello world");
    std::vector<libff::alt_bn128_G1> all_signs;
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
    }

    size_t count = 0;
    std::vector<size_t> idx_vec;
    for (size_t i = 0; i < n; ++i) {
        if (i == 3 || i == 6 || i == 9) {
            continue;
        }
     
        BlsSign bls_sign;
        libff::alt_bn128_G1 sign;
        bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &sign);
        ASSERT_EQ(
            bls_sign.Verify(t, n, sign, hash, dkg[i].local_publick_key_),
            kBlsSuccess);
        all_signs.push_back(sign);


        idx_vec.push_back(i + 1);
        ++count;
        if (count >= t) {
            break;
        }
    }

    crypto::Bls bls_instance = crypto::Bls(t, n);
    auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
        all_signs,
        lagrange_coeffs);

    for (uint32_t i = 0; i < n; ++i) {
        BlsSign bls_sign;
        ASSERT_EQ(
            bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
            kBlsSuccess);
    }
}

TEST_F(TestBls, ThreeRatioFail) {
    // t = 7, n = 10
    static const uint32_t t = 7;
    static const uint32_t n = 10;

    BlsDkg dkg[n] = {
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
        {0, 0, libff::alt_bn128_Fr::zero(), libff::alt_bn128_G2::zero(), libff::alt_bn128_G2::zero()},
    };
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = "127.0.0.1";
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].OnNewElectionBlock(1, members);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].local_member_index_ = i;
        dkg[i].BroadcastVerfify();
        verify_brd_msgs.push_back(dkg[i].ver_brd_msg_);
        dkg[i].DumpContribution();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                verify_brd_msgs[i]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // swap sec key
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].SwapSecKey();
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }

            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].all_secret_key_contribution_[i][3] = libff::alt_bn128_Fr::zero();
        dkg[i].all_secret_key_contribution_[i][6] = libff::alt_bn128_Fr::zero();
        dkg[i].all_secret_key_contribution_[i][7] = libff::alt_bn128_Fr::zero();
        dkg[i].all_secret_key_contribution_[i][9] = libff::alt_bn128_Fr::zero();
        dkg[i].invalid_node_map_[3] = 9;
        dkg[i].invalid_node_map_[6] = 9;
        dkg[i].invalid_node_map_[7] = 9;
        dkg[i].invalid_node_map_[9] = 9;
    }

    // sign and verify
    auto hash = common::Hash::Sha256("hello world");
    std::vector<libff::alt_bn128_G1> all_signs;
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
        ASSERT_TRUE(dkg[i].finished_);
    }

    size_t count = 0;
    std::vector<size_t> idx_vec;
    for (size_t i = 0; i < n; ++i) {
        if (i == 3 || i == 6 || i == 7 || i == 9) {
            continue;
        }

        BlsSign bls_sign;
        libff::alt_bn128_G1 sign;
        bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &sign);
        ASSERT_EQ(
            bls_sign.Verify(t, n, sign, hash, dkg[i].local_publick_key_),
            kBlsSuccess);
        all_signs.push_back(sign);
        idx_vec.push_back(i + 1);
        ++count;
        if (count >= t) {
            break;
        }
    }

    try {
        crypto::Bls bls_instance = crypto::Bls(t, n);
        auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
        libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
            all_signs,
            lagrange_coeffs);

        for (uint32_t i = 0; i < n; ++i) {
            BlsSign bls_sign;
            ASSERT_EQ(
                bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
                kBlsSuccess);
        }
        ASSERT_TRUE(false);
    } catch (...) {
        ASSERT_TRUE(true);
    }
}

}  // namespace test

}  // namespace bls

}  // namespace tenon
