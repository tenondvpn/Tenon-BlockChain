#pragma once

#include <unordered_map>
#include <mutex>

#include "common/bloom_filter.h"
#include "common/tick.h"
#include "election/elect_utils.h"
#include "election/elect_node_detail.h"

namespace tenon {

namespace elect {

class ElectPoolManager;

class ElectWaitingNodes {
public:
    ElectWaitingNodes(uint32_t waiting_shard_id, ElectPoolManager* pool_manager);
    ~ElectWaitingNodes();
    void UpdateWaitingNodes(
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter);
    void NewElectBlockClear();
    void GetValidWaitingNodes(std::vector<NodeDetailPtr>& nodes);
    void AddNewNode(NodeDetailPtr& node_ptr);
    void RemoveNodes(const std::vector<NodeDetailPtr>& nodes);
    void GetAllValidNodes(
        uint64_t time_offset_milli,
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes);

private:
    void UpdateNodeHeartbeat();
    void SendConsensusNodes();

    std::unordered_map<std::string, NodeDetailPtr> consensus_waiting_count_;
    std::mutex consensus_waiting_count_mutex_;
    uint32_t waiting_shard_id_{ 0 };
    ElectPoolManager* pool_manager_{ nullptr };
    std::unordered_map<std::string, NodeDetailPtr> node_map_;
    std::mutex node_map_mutex_;
    common::Tick heartbeat_tick_;
    common::Tick waiting_nodes_tick_;

    DISALLOW_COPY_AND_ASSIGN(ElectWaitingNodes);
};

typedef std::shared_ptr<ElectWaitingNodes> ElectWaitingNodesPtr;

};  // namespace elect

};  // namespace tenon