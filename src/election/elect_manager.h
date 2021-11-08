#pragma once

#include <mutex>
#include <memory>
#include <map>
#include <unordered_set>

#include "common/utils.h"
#include "common/tick.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"
#include "election/elect_pool_manager.h"
#include "election/member_manager.h"
#include "election/height_with_elect_blocks.h"
#include "election/elect_node_detail.h"
#include "network/shard_network.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace elect {

typedef network::ShardNetwork<ElectDht> ElectNode;
typedef std::shared_ptr<ElectNode> ElectNodePtr;

class ElectManager {
public:
    static ElectManager* Instance();
    int Join(uint32_t network_id);
    int Quit(uint32_t network_id);
    uint64_t latest_height(uint32_t network_id);
    int CreateElectTransaction(
        uint32_t shard_netid,
        uint64_t final_statistic_block_height,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info);
    int BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info);
    void OnTimeBlock(uint64_t tm_block_tm);
    void OnNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block);
    int GetElectionTxInfo(bft::protobuf::TxInfo& tx_info);
    elect::MembersPtr GetNetworkMembersWithHeight(uint64_t elect_height, uint32_t network_id);
    uint32_t GetMemberCountWithHeight(uint64_t elect_height, uint32_t network_id);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    elect::BftMemberPtr GetMemberWithId(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint32_t network_id);
    std::shared_ptr<MemberManager> GetMemberManager(uint32_t network_id);
    elect::MembersPtr GetWaitingNetworkMembers(uint32_t network_id);
    bool IsIdExistsInAnyShard(uint32_t network_id, const std::string& id);
    bool IsIpExistsInAnyShard(uint32_t network_id, const std::string& ip);

    libff::alt_bn128_G2 GetCommonPublicKey(uint64_t height, uint32_t network_id) {
        return height_with_block_.GetCommonPublicKey(height, network_id);
    }

    std::unordered_set<std::string> leaders(uint32_t network_id) {
        std::lock_guard<std::mutex> guard(network_leaders_mutex_);
        auto iter = network_leaders_.find(network_id);
        if (iter != network_leaders_.end()) {
            return iter->second;
        }

        return {};
    }
    
    bool IsSuperLeader(uint32_t network_id, const std::string& id) {
        std::lock_guard<std::mutex> guard(network_leaders_mutex_);
        auto iter = network_leaders_.find(network_id);
        if (iter != network_leaders_.end()) {
            return iter->second.find(id) != iter->second.end();
        }

        return false;
    }

    bool LocalNodeIsSuperLeader() {
        return local_node_is_super_leader_;
    }

    int32_t local_node_pool_mod_num() {
        return local_node_pool_mod_num_;
    }

    int32_t local_node_member_index() {
        return local_node_member_index_;
    }

    elect::BftMemberPtr local_mem_ptr(uint32_t network_id) {
        return local_mem_ptr_[network_id];
    }

    std::unordered_set<uint32_t> valid_shard_networks() {
        std::lock_guard<std::mutex> guard(valid_shard_networks_mutex_);
        return valid_shard_networks_;
    }

    uint64_t waiting_elect_height(uint32_t network_id) {
        return waiting_elect_height_[network_id];
    }

    uint32_t joined_consensus_network_id() const {
        return joined_consensus_network_id_;
    }

private:
    ElectManager();
    ~ElectManager();

    void HandleMessage(const transport::TransportMessagePtr& header);
    void WaitingNodeSendHeartbeat();
    void AddNewNodeWithIdAndIp(uint32_t network_id, const std::string& id, const std::string& ip);
    void ClearExistsNetwork(uint32_t network_id);
    void ChangeInvalidLeader(uint32_t network_id, uint32_t leader_index);
    void UpdatePrevElectMembers(
        const elect::MembersPtr& members,
        protobuf::ElectBlock& elect_block,
        bool* elected,
        std::vector<std::string>* pkey_str_vect);
    bool ProcessPrevElectMembers(
        protobuf::ElectBlock& elect_block,
        bool* elected);
    void ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool* elected);
    bool NodeHasElected(uint32_t network_id, const std::string& node_id);
    void ElectedToConsensusShard(protobuf::ElectBlock& elect_block, bool elected);

    static const uint64_t kWaitingHeartbeatPeriod = 3000000llu;

    // visit not frequently, just mutex lock
    std::map<uint32_t, ElectNodePtr> elect_network_map_;
    std::mutex elect_network_map_mutex_;
    std::shared_ptr<ElectNode> elect_node_ptr_{ nullptr };
    ElectPoolManager pool_manager_;
    common::Tick create_elect_block_tick_;
    std::unordered_set<uint64_t> added_height_;
    uint64_t elect_net_heights_map_[network::kConsensusShardEndNetworkId];
    std::mutex elect_members_mutex_;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> network_leaders_;
    std::mutex network_leaders_mutex_;
    std::unordered_set<uint32_t> valid_shard_networks_;
    std::mutex valid_shard_networks_mutex_;
    common::Tick waiting_hb_tick_;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> added_net_id_set_;
    std::mutex added_net_id_set_mutex_;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> added_net_ip_set_;
    std::mutex added_net_ip_set_mutex_;
    volatile bool local_node_is_super_leader_{ false };
    volatile int32_t local_node_pool_mod_num_{ -1 };
    volatile int32_t local_node_member_index_{ -1 };
    MembersPtr members_ptr_[network::kConsensusShardEndNetworkId];
    MembersPtr waiting_members_ptr_[network::kConsensusShardEndNetworkId];
    uint64_t waiting_elect_height_[network::kConsensusShardEndNetworkId];
    std::shared_ptr<MemberManager> mem_manager_ptr_[network::kConsensusShardEndNetworkId];
    int32_t latest_member_count_[network::kConsensusShardEndNetworkId];
    int32_t latest_leader_count_[network::kConsensusShardEndNetworkId];
    elect::BftMemberPtr local_mem_ptr_[network::kConsensusShardEndNetworkId];
    elect::NodeIndexMapPtr node_index_map_[network::kConsensusShardEndNetworkId];
    HeightWithElectBlock height_with_block_;
    BftMemberPtr pool_mod_leaders_[common::kInvalidPoolIndex];
    std::set<std::string> prev_elected_ids_;
    std::set<std::string> now_elected_ids_;

    DISALLOW_COPY_AND_ASSIGN(ElectManager);
};

}  // namespace elect

}  // namespace tenon
