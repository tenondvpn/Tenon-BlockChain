#include "election/elect_pool.h"

#include <algorithm>

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
    elect_nodes_ = nodes;
}

void ElectPool::FtsGetNodes(
        bool weed_out,
        uint32_t count,
        common::BloomFilter* nodes_filter,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::vector<NodeDetailPtr>& res_nodes) {
    auto sort_vec = src_nodes;
    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceCompare);
    SmoothFtsValue((src_nodes.size() - (src_nodes.size() / 3)), sort_vec);
    std::set<void*> tmp_res_nodes;
    std::mt19937_64 g2(vss::VssManager::Instance()->EpochRandom());
    while (tmp_res_nodes.size() < count) {
        common::FtsTree fts_tree;
        for (auto iter = src_nodes.begin(); iter != src_nodes.end(); ++iter) {
            void* data = (void*)&(*iter);
            if (tmp_res_nodes.find(data) != tmp_res_nodes.end()) {
                continue;
            }

            uint64_t fts_value = (*iter)->fts_value;
            if (weed_out) {
                fts_value = common::kTenonMaxAmount - fts_value;
            }

            fts_tree.AppendFtsNode(fts_value, data);
        }

        fts_tree.CreateFtsTree();
        void* data = fts_tree.GetOneNode(g2);
        if (data == nullptr) {
            continue;
        }

        tmp_res_nodes.insert(data);
        NodeDetailPtr node_ptr = *((NodeDetailPtr*)data);
        res_nodes.push_back(node_ptr);
        nodes_filter->Add(common::Hash::Hash64(node_ptr->id));
    }
}

void ElectPool::GetAllValidNodes(
        uint64_t time_offset_milli,
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

void ElectPool::SmoothFtsValue(
        int32_t count,
        std::vector<NodeDetailPtr>& src_nodes) {
    assert(src_nodes.size() > count);
    double min_acc_sum = common::kInvalidUint64;
    int32_t min_acc_index = 0;
    int32_t dev_count = (int32_t)src_nodes.size() - count;
    for (int32_t i = 0; i < dev_count; ++i) {
        double tmp_sum = 0;
        for (uint32_t j = i; j < i + count; ++j) {
            tmp_sum += src_nodes[j]->choosed_balance;
        }

        double mean = tmp_sum / count;
        double acc_sum = 0;
        for (int32_t j = i; j < i + count; ++j) {
            acc_sum += (src_nodes[j]->choosed_balance - mean) * (src_nodes[j]->choosed_balance - mean);
        }

        if (acc_sum < min_acc_sum) {
            min_acc_sum = acc_sum;
            min_acc_index = i;
        }
    }

    for (int32_t i = min_acc_index; i < min_acc_index + count; ++i) {
        src_nodes[i]->fts_value = src_nodes[i]->choosed_balance;
    }

    for (int32_t i = min_acc_index - 1; i >= 0; --i) {
        if (src_nodes[i + 1]->fts_value > kSmoothGradientAmount * 2) {
            src_nodes[i]->fts_value = src_nodes[i + 1]->fts_value - kSmoothGradientAmount;
        } else {
            src_nodes[i]->fts_value = kSmoothGradientAmount;
        }
    }

    for (int32_t i = min_acc_index + count; i < (int32_t)src_nodes.size(); ++i) {
        src_nodes[i]->fts_value = src_nodes[i - 1]->fts_value + kSmoothGradientAmount;
    }
}
};  // namespace elect

};  //  namespace tenon
