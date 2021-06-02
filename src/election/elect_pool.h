#pragma once

#include <unordered_map>
#include <mutex>

#include "common/bloom_filter.h"
#include "election/elect_utils.h"
#include "election/elect_node_detail.h"

namespace tenon {

namespace elect {

class ElectPool {
public:
    explicit ElectPool(uint32_t net_id);
    ~ElectPool();
    void ReplaceWithElectNodes(const std::vector<NodeDetailPtr>& nodes);
    // now shard min balance and max balance is 2/3 nodes middle balance
    void GetAllValidNodes(
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes);

private:
    void CreateFtsTree(const std::vector<NodeDetailPtr>& src_nodes);

    std::unordered_map<std::string, NodeDetailPtr> node_map_;
    std::mutex node_map_mutex_;
    std::vector<NodeDetailPtr> elect_nodes_;
    uint32_t network_id_{ 0 };
    uint64_t smooth_min_balance_{ 0 };
    uint64_t smooth_max_balance_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ElectPool);
};

typedef std::shared_ptr<ElectPool> ElectPoolPtr;

};  // namespace elect

};  //  namespace tenon
