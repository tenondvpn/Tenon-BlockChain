#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>

#include "common/random.h"
#include "common/hash.h"
#include "dht/dht_key.h"
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
        auto member = std::make_shared<elect::BftMember>(
            network::kConsensusShardBeginNetworkId, id, pubkey_str, i, "", i == 0 ? 0 : -1);
        member->public_ip = 234234;
        member->public_port = 123;
        members->push_back(member);
    }

    std::vector<transport::protobuf::Header> verify_brd_msgs;
    for (uint32_t i = 0; i < n; ++i) {
        SetGloableInfo(pri_vec[i], network::kConsensusShardBeginNetworkId);
        dkg[i].dkg_verify_brd_timer_.Destroy();
        dkg[i].dkg_swap_seckkey_timer_.Destroy();
        dkg[i].dkg_finish_timer_.Destroy();
        dkg[i].OnNewElectionBlock(1, members);
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
        for (uint32_t j = i + 1; j < n; ++j) {
            SetGloableInfo(pri_vec[j], network::kConsensusShardBeginNetworkId);
            auto msg_ptr = std::make_shared<transport::protobuf::Header>(
                dkg[i].sec_swap_msgs_[j]);
            dkg[j].HandleMessage(msg_ptr);
        }
    }

    // sign and verify
    std::vector<std::string> bls_prikeys = {
    "2294693333552044080236769000059483663349841417751624599070777562397970206650"
    ,"9718414207548464167165618385514348390474780319573951458084426396122522537248"
    ,"1187464956706038301308266996433335881352532469969015590996216356913300885892"
    ,"7021115389803627837638493868693449613558067871756025910676203339886238834493"
    ,"15403367425616042974490681596328874853660039374408987833933473193279502680417"
    ,"588230559585539188092710036343928823705566001364061091524453759583963305108"
    ,"20259183662481234090845598531755534173347381367791894411032640132038182207070"
    ,"9942694289778765935160998983491539252291152381762353229750261954699167273719"
    ,"18676053144295551319234335109892238193707357842946808123300835109666387143083"
    ,"10399808818510633204897358083524087266673150922216610202074430328426704330670"
    };
    auto hash = common::Encode::HexEncode(common::Hash::Sha256("hello world"));
    std::vector<libff::alt_bn128_G1> all_signs(n);
    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].Finish();
        BlsSign bls_sign;
        dkg[i].local_sec_key_ = libff::alt_bn128_Fr(bls_prikeys[i].c_str());
        ASSERT_EQ(
            bls_sign.Sign(t, n, dkg[i].local_sec_key_, hash, &all_signs[i]),
            kBlsSuccess);
//         ASSERT_EQ(
//             bls_sign.Verify(t, n, all_signs[i], hash, dkg[i].local_publick_key_),
//             kBlsSuccess);
    }

    std::vector<size_t> idx_vec(t);
    for (size_t i = 0; i < t; ++i) {
        idx_vec[i] = i + 1;
    }

    signatures::Bls bls_instance = signatures::Bls(t, n);
    auto lagrange_coeffs = bls_instance.LagrangeCoeffs(idx_vec);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(
        all_signs,
        lagrange_coeffs);

    std::vector<std::string> pkey_str;
    pkey_str.push_back("8450064501504853443387960803404029182694431849098238527879028136828299206497");
    pkey_str.push_back("1010619530225578161015298718462689657916059555100918119830682036106786237669");
    pkey_str.push_back("4571649803337987184358497258959797622246195872870910425367355814518813580607");
    pkey_str.push_back("7331594472031789866455650255249235107494510614949823829609836481391432392555");
    BLSPublicKey pkey(std::make_shared< std::vector< std::string > >(pkey_str), t, n);

    for (uint32_t i = 0; i < n; ++i) {
        dkg[i].common_public_key_ = *pkey.getPublicKey();
        BlsSign bls_sign;
        ASSERT_EQ(
            bls_sign.Verify(t, n, agg_sign, hash, dkg[i].common_public_key_),
            kBlsSuccess);
    }

}

}  // namespace test

}  // namespace bls

}  // namespace tenon
