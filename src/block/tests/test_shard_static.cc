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
#include "election/elect_node_detail.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/secp256k1.h"
#include "security/crypto_utils.h"
#include "security/security.h"
#include "security/ecdh_create_key.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread.h"
#include "transport/transport_utils.h"
#define private public
#include "block/shard_statistic.h"
#include "bft/dispatch_pool.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"

namespace tenon {

namespace block {

namespace test {

class TestShardStatic : public testing::Test {
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
        common::global_stop = true;
    }

    static void SetGloableInfo(const std::string& private_key, uint32_t network_id) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        security::Security::Instance()->set_prikey(std::make_shared<security::PrivateKey>(prikey));
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
            security::Security::Instance()->str_pubkey(),
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

// tenon::transport::TransportPtr TestShardStatic::transport_ = nullptr;

TEST_F(TestShardStatic, AllSuccess) {
    common::GlobalInfo::Instance()->set_network_id(3);
    static const uint32_t n = 1024;
    elect::MembersPtr members = std::make_shared<elect::Members>();
    std::vector<std::string> pri_vec;
    for (uint32_t i = 0; i < n; ++i) {
        pri_vec.push_back(common::Random::RandomString(32));
    }

    std::set<int32_t> leader_idx;
    while(true) {
        leader_idx.insert(rand() % 1024);
        if (leader_idx.size() >= 256) {
            break;
        }
    }

    std::vector<int32_t> valid_node_idx;
    for (int32_t i = 0; i < 1024; ++i) {
        valid_node_idx.push_back(i);
    }
    
    std::random_shuffle(valid_node_idx.begin(), valid_node_idx.end());
    int32_t pool_idx = 0;
    std::vector<elect::BftMemberPtr> leaders;
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
        if (leader_idx.find(i) != leader_idx.end()) {
            member->pool_index_mod_num = pool_idx++;
            leaders.push_back(member);
        }
    }

    libff::alt_bn128_G2 cpk;
    elect::ElectManager::Instance()->height_with_block_.AddNewHeightBlock(10, 3, members, cpk);
    static const int32_t kValidCount = 1024 * 2 / 3 + 1;
    static const int32_t kBlockCount = 10;
    uint64_t block_height = 0;
    for (auto iter = leaders.begin(); iter != leaders.end(); ++iter) {
        for (int32_t bidx = 0; bidx < kBlockCount; ++bidx) {
            auto block_item = std::make_shared<bft::protobuf::Block>();
            block_item->set_electblock_height(10);
            block_item->set_timeblock_height(9);
            block_item->set_network_id(3);
            block_item->set_height(++block_height);
            block_item->set_leader_index((*iter)->index);
            common::Bitmap bitmap(1024);
            std::vector<int32_t> random_set_node = valid_node_idx;
            std::random_shuffle(random_set_node.begin(), random_set_node.end());
            for (int32_t i = 0; i < 10; ++i) {
                bitmap.Set(random_set_node[i]);
            }

            for (int32_t i = 0; i < valid_node_idx.size(); ++i) {
                if (bitmap.valid_count() >= kValidCount) {
                    break;
                }

                bitmap.Set(valid_node_idx[i]);
            }

            auto datas = bitmap.data();
            for (uint32_t i = 0; i < datas.size(); ++i) {
                block_item->add_bitmap(datas[i]);
            }

            int32_t tx_size = rand() % 10 + 1;
            int32_t start_pool_idx = (*iter)->pool_index_mod_num;
            for (int32_t i = 0; i < tx_size; ++i) {
                auto tx = block_item->add_tx_list();
                tx->set_type(common::kConsensusTransaction);
                bft::DispatchPool::Instance()->tx_pool_.AddTxCount(start_pool_idx);
                start_pool_idx = (start_pool_idx + leaders.size()) % 256;
            }

            ShardStatistic::Instance()->AddStatistic(block_item);
        }
    }

    block::protobuf::StatisticInfo statistic_info;
    ShardStatistic::Instance()->GetStatisticInfo(9, &statistic_info);
}

}  // namespace test

}  // namespace block

}  // namespace tenon
