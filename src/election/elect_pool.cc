#include "election/elect_pool.h"

#include "common/fts_tree.h"
#include "common/global_info.h"
#include "vss/vss_manager.h"
#include "network/network_utils.h"
#include "election/member_manager.h"

namespace tenon {

namespace elect {

ElectPool::ElectPool(uint32_t netid) : network_id_(netid) {}

ElectPool::~ElectPool() {}

void ElectPool::ReplaceWithElectNodes(const std::vector<NodeDetailPtr>& nodes) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    elect_nodes_.clear();
    for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
        auto copy_ptr = std::make_shared<ElectNodeDetail>();
        copy_ptr->id = (*iter)->id;
        copy_ptr->public_key = (*iter)->public_key;
        copy_ptr->public_ip = (*iter)->public_ip;
        copy_ptr->public_port = (*iter)->public_port;
        copy_ptr->dht_key = (*iter)->dht_key;
        copy_ptr->choosed_height = (uint64_t)(*iter)->choosed_height;
        copy_ptr->choosed_balance = (uint64_t)(*iter)->choosed_balance;
        copy_ptr->balance_diff = (*iter)->balance_diff;
        copy_ptr->join_tm = (*iter)->join_tm;
        copy_ptr->heatbeat_succ_count = (*iter)->heatbeat_succ_count;
        copy_ptr->heatbeat_fail_count = (*iter)->heatbeat_fail_count;
        copy_ptr->height_with_balance = (*iter)->height_with_balance;
        copy_ptr->success_tx_count = (uint32_t)(*iter)->success_tx_count;
        copy_ptr->fts_value = (*iter)->fts_value;
        copy_ptr->valid_node_set = (*iter)->valid_node_set;
        copy_ptr->pool_index_mod_num = -1;
        elect_nodes_.push_back(copy_ptr);
    }
}

void ElectPool::GetAllValidNodes(
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes) {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        if ((network_id_ >= network::kConsensusShardBeginNetworkId &&
                network_id_ < network::kConsensusShardEndNetworkId) ||
                network_id_ == network::kRootCongressNetworkId) {
            nodes = elect_nodes_;
            for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
                nodes_filter.Add(common::Hash::Hash64((*iter)->id));
            }
        }
    }

    std::sort(nodes.begin(), nodes.end(), ElectNodeIdCompare);
}

};  // namespace elect

};  //  namespace tenon
