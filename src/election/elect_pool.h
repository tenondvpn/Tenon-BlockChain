#pragma once

#include <unordered_map>
#include <mutex>

#include "common/tick.h"
#include "common/bloom_filter.h"
#include "election/elect_utils.h"
#include "election/elect_node_detail.h"

namespace tenon {

namespace elect {

class ElectPool {
public:
    explicit ElectPool(uint32_t net_id);
    ~ElectPool();
    void AddNewNode(NodeDetailPtr& node_ptr);
    void RemoveNodes(const std::vector<NodeDetailPtr>& nodes);
    void ReplaceWithElectNodes(const std::vector<NodeDetailPtr>& nodes);
    void FtsGetNodes(
        bool weed_out,
        uint32_t count,
        common::BloomFilter& nodes_filter,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::vector<NodeDetailPtr>& res_nodes);
    // now shard min balance and max balance is 2/3 nodes middle balance
    void GetAllValidNodes(
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes);

private:
    void UpdateNodeHeartbeat();
    void CreateFtsTree(const std::vector<NodeDetailPtr>& src_nodes);
    void SmoothFtsValue(
        int32_t count,
        std::vector<NodeDetailPtr>& src_nodes);
    std::unordered_map<std::string, NodeDetailPtr> node_map_;
    std::mutex node_map_mutex_;
    std::vector<NodeDetailPtr> elect_nodes_;
    common::Tick heartbeat_tick_;
    uint32_t network_id_{ 0 };
    uint64_t smooth_min_balance_{ 0 };
    uint64_t smooth_max_balance_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ElectPool);
};

typedef std::shared_ptr<ElectPool> ElectPoolPtr;

};  // namespace elect

};  //  namespace tenon
