#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "election/member_manager.h"
#include "network/network_utils.h"
#include "security/crypto_utils.h"
#include "security/secp256k1.h"

namespace tenon {

namespace bft {

namespace test {

class TestMemberManager : public testing::Test {
public:
    static void SetUpTestCase() {
        common::global_stop = true;
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

private:

};

TEST_F(TestMemberManager, SetNetworkMember) {
    std::map<uint32_t, elect::MembersPtr> in_members;
    std::map<uint32_t, elect::MembersPtr> out_members;
    std::map<uint32_t, elect::NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map_;
    for (int32_t i = 0; i < 1024; ++i) {
        auto net_id = network::kConsensusShardBeginNetworkId + std::rand() % 5;
        auto iter = in_members.find(net_id);
        if (iter == in_members.end()) {
            in_members[net_id] = std::make_shared<elect::Members>();
            in_index_members[net_id] = std::make_shared<
                std::unordered_map<std::string, uint32_t>>();
            begin_index_map_[net_id] = 0;
        }

        security::PrivateKey private_key;
        security::PublicKey pubkey(private_key);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeySize);
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);;
        security::CommitSecret secret;
        in_members[net_id]->push_back(std::make_shared<elect::BftMember>(
            net_id, id, pubkey_str, begin_index_map_[net_id], "", 0, "", -1));
        in_index_members[net_id]->insert(std::make_pair(id, begin_index_map_[net_id]));
        dht::NodePtr node = std::make_shared<dht::Node>(
            id,
            "dht_key",
            0,
            false,
            "127.0.0.1",
            0,
            "127.0.0.1",
            0,
            pubkey_str,
            "bft");
        ++begin_index_map_[net_id];
    }

    elect::MemberManager mem_manager;
    for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
        auto index_map_iter = in_index_members.find(iter->first);
        ASSERT_TRUE(index_map_iter != in_index_members.end());
        mem_manager.SetNetworkMember(
            iter->first,
            iter->second,
            index_map_iter->second);
        auto members_ptr = mem_manager.GetNetworkMembers(iter->first);
        EXPECT_EQ(members_ptr->size(), iter->second->size());
        EXPECT_TRUE(mem_manager.IsLeader(iter->first, iter->second->at(0)->id, 0));
        auto check_node_index = iter->second->size() - 1;
        EXPECT_EQ(
            mem_manager.GetMemberIndex(iter->first, iter->second->at(check_node_index)->id),
            check_node_index);
        EXPECT_EQ(
            mem_manager.GetMember(iter->first, check_node_index)->id,
            iter->second->at(check_node_index)->id);
        EXPECT_EQ(
            mem_manager.GetMember(iter->first, iter->second->at(check_node_index)->id)->id,
            iter->second->at(check_node_index)->id);
    }
}

}  // namespace test

}  // namespace bft

}  // namespace tenon
