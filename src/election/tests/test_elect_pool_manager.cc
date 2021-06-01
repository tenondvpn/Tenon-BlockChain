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

class TestElectPoolManager : public testing::Test {
public:
    static void SetUpTestCase() {    
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
        EXPECT_EQ(pubkey.Serialize(pubkey_str, compress), security::kPublicKeyUncompressSize);
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
            tx_info->set_balance(common::Random::RandomUint64() % common::kTenonMaxAmount);
        }

        elect_pool_manager_.UpdateNodeInfoWithBlock(block_info);
    }

private:
    ElectPoolManager elect_pool_manager_;
};

TEST_F(TestElectPoolManager, All) {
    const uint32_t kMemberCount = 31;
    CreateElectBlocks(kMemberCount, network::kConsensusShardBeginNetworkId);
    for (uint32_t i = 0; i < 20; ++i) {
        UpdateNodeInfoWithBlock(kMemberCount, i);
    }

    bft::protobuf::BftMessage bft_msg;
    ASSERT_EQ(elect_pool_manager_.LeaderCreateElectionBlockTx(
        network::kConsensusShardBeginNetworkId,
        bft_msg), kElectSuccess);
    ASSERT_EQ(elect_pool_manager_.BackupCheckElectionBlockTx(bft_msg), kElectSuccess);
}

}  // namespace test

}  // namespace elect

}  // namespace tenon
