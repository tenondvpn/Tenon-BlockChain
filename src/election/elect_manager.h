#pragma once

#include <mutex>
#include <memory>
#include <map>
#include <unordered_set>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "network/shard_network.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"
#include "election/elect_pool_manager.h"
#include "election/member_manager.h"

namespace tenon {

namespace elect {

typedef network::ShardNetwork<ElectDht> ElectNode;
typedef std::shared_ptr<ElectNode> ElectNodePtr;

class ElectManager {
public:
    static ElectManager* Instance();
    int Join(uint32_t network_id);
    int Quit(uint32_t network_id);
    void ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool load_from_db);
    uint64_t latest_height(uint32_t network_id);
    int CreateElectTransaction(
        uint32_t shard_netid,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info);
    int BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info);
    void OnTimeBlock(uint64_t tm_block_tm);
    int GetElectionTxInfo(bft::protobuf::TxInfo& tx_info);

    // get member
    int32_t IsLeader(uint64_t elect_height, uint32_t network_id, const std::string& node_id);
    uint32_t GetMemberIndex(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint64_t elect_height, uint32_t network_id);
    elect::BftMemberPtr GetMember(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id);
    elect::BftMemberPtr GetMember(uint64_t elect_height, uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint64_t elect_height, uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint64_t elect_height, uint32_t network_id);
    void SetNetworkMember(
        uint64_t elect_height,
        uint32_t network_id,
        elect::MembersPtr& members_ptr,
        elect::NodeIndexMapPtr& node_index_map,
        int32_t leader_count);
    bool IsValidShardLeaders(uint64_t elect_height, uint32_t network_id, const std::string& id);
    int32_t IsLeader(uint32_t network_id, const std::string& node_id);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMemberWithId(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint32_t network_id);
    bool IsValidShardLeaders(uint32_t network_id, const std::string& id);

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

    std::unordered_set<uint32_t> valid_shard_networks() {
        std::lock_guard<std::mutex> guard(valid_shard_networks_mutex_);
        return valid_shard_networks_;
    }

    bool IsIdExistsInAnyShard(uint32_t network_id, const std::string& id);
    bool IsIpExistsInAnyShard(uint32_t network_id, const std::string& ip);

private:
    ElectManager();
    ~ElectManager();

    void HandleMessage(transport::protobuf::Header& header);
    void WaitingNodeSendHeartbeat();
    void AddNewNodeWithIdAndIp(uint32_t network_id, const std::string& id, const std::string& ip);
    void ClearExistsNetwork(uint32_t network_id);

    static const uint64_t kWaitingHeartbeatPeriod = 30000000llu;

    // visit not frequently, just mutex lock
    std::map<uint32_t, ElectNodePtr> elect_network_map_;
    std::mutex elect_network_map_mutex_;
    std::shared_ptr<ElectNode> elect_node_ptr_{ nullptr };
    ElectPoolManager pool_manager_;
    common::Tick create_elect_block_tick_;
    std::unordered_map<uint64_t, std::shared_ptr<MemberManager>> elect_members_;
    std::unordered_map<uint32_t, uint64_t> elect_net_heights_map_;
    std::mutex elect_members_mutex_;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> network_leaders_;
    std::mutex network_leaders_mutex_;
    std::unordered_set<uint32_t> valid_shard_networks_;
    std::mutex valid_shard_networks_mutex_;
    common::Tick waiting_hb_tick_;
    std::unordered_set<std::string> added_id_set_;
    std::mutex added_id_set_mutex_;
    std::unordered_set<std::string> added_ip_set_;
    std::mutex added_ip_set_mutex_;
    std::atomic<bool> local_node_is_super_leader_{ false };

    DISALLOW_COPY_AND_ASSIGN(ElectManager);
};

}  // namespace elect

}  // namespace tenon
