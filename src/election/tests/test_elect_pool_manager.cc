#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "bzlib.h"

#define private public
#include "election/elect_pool_manager.h"
#include "security/secp256k1.h"
#include "security/crypto_utils.h"
#include "network/network_utils.h"
#include "common/random.h"

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

    void CreateElectBlocks(int32_t member_count, uint32_t network_id) {
        std::map<uint32_t, MembersPtr> in_members;
        std::map<uint32_t, NodeIndexMapPtr> in_index_members;
        std::map<uint32_t, uint32_t> begin_index_map_;
        for (int32_t i = 0; i < member_count; ++i) {
            char from_data[128];
            snprintf(from_data, sizeof(from_data), "%04d%s", i, kRootNodeIdEndFix);
            std::string prikey = common::Encode::HexDecode(from_data);

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
                0,
                ""));
            in_index_members[net_id]->insert(std::make_pair(GetIdByPrikey(prikey), begin_index_map_[net_id]));
            ++begin_index_map_[net_id];
        }

        for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
            auto index_map_iter = in_index_members.find(iter->first);
            assert(index_map_iter != in_index_members.end());
            elect_pool_manager_.NetworkMemberChange(iter->first, iter->second);
        }
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

private:
    ElectPoolManager elect_pool_manager_;
};

TEST_F(TestElectPoolManager, All) {
    const uint32_t kMemberCount = 31;
    const uint32_t kWaitingCount = 11;
    CreateElectBlocks(kMemberCount, network::kConsensusShardBeginNetworkId);
    for (uint32_t i = 0; i < 20; ++i) {
        UpdateNodeInfoWithBlock(kMemberCount, i);
    }

    std::cout << "network::kConsensusShardBeginNetworkId + network::kConsensusWaitingShardOffset: " << (network::kConsensusShardBeginNetworkId + network::kConsensusWaitingShardOffset) << std::endl;
    AddWaitingPoolNetworkNodes(kWaitingCount, network::kConsensusShardBeginNetworkId + network::kConsensusWaitingShardOffset);
    bft::protobuf::BftMessage bft_msg;
    ASSERT_EQ(elect_pool_manager_.LeaderCreateElectionBlockTx(
        network::kConsensusShardBeginNetworkId,
        bft_msg), kElectSuccess);
    ASSERT_EQ(elect_pool_manager_.BackupCheckElectionBlockTx(bft_msg), kElectSuccess);
}

}  // namespace test

}  // namespace elect

}  // namespace tenon
