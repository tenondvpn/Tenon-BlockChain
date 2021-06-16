#pragma once

#include <mutex>
#include <memory>
#include <map>
#include <unordered_set>

#include "common/utils.h"
#include "common/tick.h"
#include "common/min_heap.h"
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
typedef std::shared_ptr<common::LimitHeap<uint64_t, 256, true>> HeightLimitHeapPtr;

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
        bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info);
    int BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info);
    // get member
    int32_t IsLeader(uint64_t elect_height, uint32_t network_id, const std::string& node_id);
    uint32_t GetMemberIndex(uint64_t elect_height, uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint64_t elect_height, uint32_t network_id);
    elect::BftMemberPtr GetMember(uint64_t elect_height, uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint64_t elect_height, uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint64_t elect_height, uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint64_t elect_height, uint32_t network_id);
    void SetNetworkMember(
        uint64_t elect_height,
        uint32_t network_id,
        elect::MembersPtr& members_ptr,
        elect::NodeIndexMapPtr& node_index_map,
        int32_t leader_count);

    int32_t IsLeader(uint32_t network_id, const std::string& node_id);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMemberWithId(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint32_t network_id);
    bool IsValidShardLeaders(const std::string& id);

    std::unordered_set<std::string> leaders() {
        std::lock_guard<std::mutex> guard(leaders_mutex_);
        return leaders_;
    }

private:
    ElectManager();
    ~ElectManager();

    void HandleMessage(transport::protobuf::Header& header);

    // visit not frequently, just mutex lock
    std::map<uint32_t, ElectNodePtr> elect_network_map_;
    std::mutex elect_network_map_mutex_;
    std::shared_ptr<ElectNode> elect_node_ptr_{ nullptr };
    ElectPoolManager pool_manager_;
    common::Tick create_elect_block_tick_;
    std::unordered_map<uint64_t, std::shared_ptr<MemberManager>> elect_members_;
    std::unordered_map<uint32_t, HeightLimitHeapPtr> elect_net_heights_map_;
    std::mutex elect_members_mutex_;
    std::unordered_set<std::string> leaders_;
    std::mutex leaders_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ElectManager);
};

}  // namespace elect

}  // namespace tenon
