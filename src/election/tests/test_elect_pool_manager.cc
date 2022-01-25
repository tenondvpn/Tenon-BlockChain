#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "bzlib.h"

#define private public
#include "election/elect_pool_manager.h"
#include "election/elect_manager.h"
#include "election/elect_manager.h"
#include "security/secp256k1.h"
#include "security/crypto_utils.h"
#include "security/security.h"
#include "network/network_utils.h"
#include "common/random.h"
#include "common/time_utils.h"

namespace tenon {

namespace elect {

namespace test {

static const char* kRootNodeIdEndFix = "2f72f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b4851";
static const char* kWaitingNodeIdEndFix = "1f72f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b4851";

class TestElectPoolManager : public testing::Test {
public:
    static void WriteDefaultLogConf(
        const std::string& log_conf_path,
        const std::string& log_path) {
        FILE* file = NULL;
        file = fopen(log_conf_path.c_str(), "w");
        if (file == NULL) {
            return;
        }
        std::string log_str = ("# log4cpp.properties\n"
            "log4cpp.rootCategory = WARN\n"
            "log4cpp.category.sub1 = WARN, programLog\n"
            "log4cpp.appender.rootAppender = ConsoleAppender\n"
            "log4cpp.appender.rootAppender.layout = PatternLayout\n"
            "log4cpp.appender.rootAppender.layout.ConversionPattern = %d [%p] %m%n\n"
            "log4cpp.appender.programLog = RollingFileAppender\n"
            "log4cpp.appender.programLog.fileName = ") + log_path + "\n" +
            std::string("log4cpp.appender.programLog.maxFileSize = 1073741824\n"
                "log4cpp.appender.programLog.maxBackupIndex = 1\n"
                "log4cpp.appender.programLog.layout = PatternLayout\n"
                "log4cpp.appender.programLog.layout.ConversionPattern = %d [%p] %m%n\n");
        fwrite(log_str.c_str(), log_str.size(), 1, file);
        fclose(file);
    }

    static void SetUpTestCase() {    
        common::global_stop = true;
        std::string config_path_ = "./";
        std::string conf_path = config_path_ + "/tenon.conf";
        std::string log_conf_path = config_path_ + "/log4cpp.properties";
        std::string log_path = config_path_ + "/tenon.log";
        WriteDefaultLogConf(log_conf_path, log_path);
        log4cpp::PropertyConfigurator::configure(log_conf_path);
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    std::string GetIdByPrikey(const std::string& private_key) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        EXPECT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        return id;
    }

    std::string GetPubkeyByPrikey(const std::string& private_key, bool compress = true) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        EXPECT_EQ(pubkey.Serialize(pubkey_str, compress), security::kPublicKeySize);
        return pubkey_str;
    }

    void CreateElectionBlockMemeber(uint32_t network_id, std::vector<std::string>& pri_vec) {
        std::map<uint32_t, elect::MembersPtr> in_members;
        std::map<uint32_t, elect::MembersPtr> out_members;
        std::map<uint32_t, elect::NodeIndexMapPtr> in_index_members;
        std::map<uint32_t, uint32_t> begin_index_map_;
        for (uint32_t i = 0; i < pri_vec.size(); ++i) {
            auto net_id = network_id;
            auto iter = in_members.find(net_id);
            if (iter == in_members.end()) {
                in_members[net_id] = std::make_shared<elect::Members>();
                in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
                begin_index_map_[net_id] = 0;
            }

            security::PrivateKey prikey(pri_vec[i]);
            security::PublicKey pubkey(prikey);
            std::string pubkey_str;
            ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
            std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
            security::CommitSecret secret;
            in_members[net_id]->push_back(std::make_shared<elect::BftMember>(
                net_id, id, pubkey_str, begin_index_map_[net_id], "", i == 0 ? 0 : -1));
            in_index_members[net_id]->insert(std::make_pair(id, begin_index_map_[net_id]));
            ++begin_index_map_[net_id];
        }

        static uint64_t elect_height = 0;
        for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
            auto index_map_iter = in_index_members.find(iter->first);
            ASSERT_TRUE(index_map_iter != in_index_members.end());
//             ElectManager::Instance()->SetNetworkMember(
//                 elect_height++,
//                 iter->first,
//                 iter->second,
//                 index_map_iter->second,
//                 1);
        }
    }

    void SetGloableInfo(const std::string& private_key, uint32_t network_id) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        security::Security::Instance()->set_prikey(std::make_shared<security::PrivateKey>(prikey));
        common::GlobalInfo::Instance()->set_id(id);
        common::GlobalInfo::Instance()->set_consensus_shard_count(1);
        common::GlobalInfo::Instance()->set_network_id(network_id);
    }

    void CreateElectBlocks(int32_t member_count, uint32_t network_id) {
        std::map<uint32_t, MembersPtr> in_members;
        std::map<uint32_t, NodeIndexMapPtr> in_index_members;
        std::map<uint32_t, uint32_t> begin_index_map_;
        std::vector<std::string> pri_vec;
        for (int32_t i = 0; i < member_count; ++i) {
            char from_data[128];
            snprintf(from_data, sizeof(from_data), "%04d%s", i, kRootNodeIdEndFix);
            std::string prikey = common::Encode::HexDecode(from_data);
            pri_vec.push_back(prikey);
            auto net_id = network_id;
            auto iter = in_members.find(net_id);
            if (iter == in_members.end()) {
                in_members[net_id] = std::make_shared<Members>();
                in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
                begin_index_map_[net_id] = 0;
            }

            in_members[net_id]->push_back(std::make_shared<BftMember>(
                net_id,
                GetIdByPrikey(prikey),
                GetPubkeyByPrikey(prikey),
                begin_index_map_[net_id],
                "",
                -1));
            in_index_members[net_id]->insert(std::make_pair(GetIdByPrikey(prikey), begin_index_map_[net_id]));
            ++begin_index_map_[net_id];
        }

        for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
            auto index_map_iter = in_index_members.find(iter->first);
            assert(index_map_iter != in_index_members.end());
            elect_pool_manager_.NetworkMemberChange(iter->first, iter->second);
        }

        SetGloableInfo(pri_vec[0], network::kConsensusShardBeginNetworkId);
        CreateElectionBlockMemeber(network_id, pri_vec);
    }

    void UpdateNodeInfoWithBlock(int32_t member_count, uint64_t height) {
        bft::protobuf::Block block_info;
        block_info.set_height(height);
        for (int32_t i = 0; i < member_count; ++i) {
            char from_data[128];
            snprintf(from_data, sizeof(from_data), "%04d%s", i, kRootNodeIdEndFix);
            std::string prikey = common::Encode::HexDecode(from_data);

            char to_data[128];
            snprintf(to_data, sizeof(to_data), "%04d%s", i + member_count + 1, kRootNodeIdEndFix);
            std::string to_prikey = common::Encode::HexDecode(to_data);

            auto tx_list = block_info.mutable_tx_list();
            auto tx_info = tx_list->Add();
            tx_info->set_from(GetIdByPrikey(prikey));
            tx_info->set_to(GetIdByPrikey(to_prikey));
            tx_info->set_from_pubkey(GetPubkeyByPrikey(prikey));
            tx_info->set_balance(common::Random::RandomUint64() % (common::kTenonMaxAmount / 1000000));
        }

        elect_pool_manager_.UpdateNodeInfoWithBlock(block_info);
    }

    void AddWaitingPoolNetworkNodes(int32_t member_count, uint32_t network_id) {
        for (int32_t i = 0; i < member_count; ++i) {
            NodeDetailPtr new_node = std::make_shared<ElectNodeDetail>();
            char from_data[128];
            snprintf(from_data, sizeof(from_data), "%04d%s", i, kWaitingNodeIdEndFix);
            std::string prikey = common::Encode::HexDecode(from_data);
            new_node->id = GetIdByPrikey(prikey);
            new_node->public_key = GetPubkeyByPrikey(prikey);
            new_node->dht_key = "";
            new_node->public_ip = "";
            new_node->public_port = 0;
            new_node->join_tm = std::chrono::steady_clock::now() - std::chrono::microseconds(kElectAvailableJoinTime + 1000);
            new_node->choosed_balance = common::Random::RandomUint64() % (common::kTenonMaxAmount / 1000000);
            elect_pool_manager_.AddWaitingPoolNode(network_id, new_node);
        }
    }

    void UpdateWaitingNodesConsensusCount(int32_t member_count) {
        common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
        std::vector<NodeDetailPtr> pick_all_vec;
        elect_pool_manager_.waiting_pool_map_[
            network::kConsensusShardBeginNetworkId +
            network::kConsensusWaitingShardOffset]->GetAllValidHeartbeatNodes(
            0, pick_all, pick_all_vec);
        for (int32_t i = 0; i < member_count; ++i) {
            char from_data[128];
            snprintf(from_data, sizeof(from_data), "%04d%s", i, kRootNodeIdEndFix);
            std::string prikey = common::Encode::HexDecode(from_data);
            elect_pool_manager_.waiting_pool_map_[
                network::kConsensusShardBeginNetworkId +
                network::kConsensusWaitingShardOffset]->UpdateWaitingNodes(
                GetIdByPrikey(prikey), pick_all);
        }
    }

private:
    ElectPoolManager elect_pool_manager_;
};

TEST_F(TestElectPoolManager, GetAllBloomFilerAndNodes) {
    const uint32_t kMemberCount = 31;
    const uint32_t kWaitingCount = 11;
    CreateElectBlocks(kMemberCount, network::kConsensusShardBeginNetworkId);
    CreateElectBlocks(kMemberCount, network::kRootCongressNetworkId);
    for (uint32_t i = 0; i < 20; ++i) {
        UpdateNodeInfoWithBlock(kMemberCount, i);
    }

    AddWaitingPoolNetworkNodes(
        kWaitingCount,
        network::kConsensusShardBeginNetworkId + network::kConsensusWaitingShardOffset);
    auto waiting_pool_ptr = elect_pool_manager_.waiting_pool_map_[
        network::kConsensusShardBeginNetworkId + network::kConsensusWaitingShardOffset];
    ASSERT_TRUE(waiting_pool_ptr != nullptr);
    ASSERT_EQ(waiting_pool_ptr->node_map_.size(), kWaitingCount);
    auto latest_time_block_tm = common::TimeUtils::TimestampSeconds() - common::kTimeBlockCreatePeriodSeconds;
    elect_pool_manager_.OnTimeBlock(latest_time_block_tm);
    UpdateWaitingNodesConsensusCount(kMemberCount);
    ASSERT_EQ(waiting_pool_ptr->all_nodes_waiting_map_.size(), 1);
    auto waiting_iter = waiting_pool_ptr->all_nodes_waiting_map_.begin();
    ASSERT_EQ(waiting_iter->second->same_root_count, kMemberCount);
    common::BloomFilter cons_all(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter cons_weed_out(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    common::BloomFilter pick_in(kBloomfilterSize, kBloomfilterHashCount);
    std::vector<NodeDetailPtr> exists_shard_nodes;
    std::vector<NodeDetailPtr> weed_out_vec;
    std::vector<NodeDetailPtr> pick_in_vec;
    int32_t leader_count = 0;
    block::protobuf::StatisticInfo statistic_info;
    uint32_t shard_netid = network::kConsensusShardBeginNetworkId;
    ASSERT_EQ(elect_pool_manager_.GetAllBloomFilerAndNodes(
        statistic_info,
        shard_netid,
        &cons_all,
        &cons_weed_out,
        &pick_all,
        &pick_in,
        exists_shard_nodes,
        weed_out_vec,
        pick_in_vec,
        &leader_count), kElectSuccess);
    std::cout << "exists_shard_nodes count: " << exists_shard_nodes.size()
        << ", weed_out_vec size: " << weed_out_vec.size()
        << ", pick_in_vec: " << pick_in_vec.size()
        << ", leader_count: " << leader_count << std::endl;
}

}  // namespace test

}  // namespace elect

}  // namespace tenon
