#include "election/elect_pool.h"

#include <algorithm>

#include "common/fts_tree.h"
#include "common/global_info.h"
#include "vss/vss_manager.h"
#include "election/member_manager.h"

namespace tenon {

namespace elect {

ElectPool::ElectPool() {
    heartbeat_tick_.CutOff(
        30llu * 60llu * 10000000llu,
        std::bind(&ElectPool::UpdateNodeHeartbeat, this));
}

ElectPool::~ElectPool() {}

void ElectPool::AddNewNode(NodeDetailPtr& node_ptr) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    node_map_[node_ptr->id] = node_ptr;
}

void ElectPool::RemoveNodes(const std::vector<NodeDetailPtr>& nodes) {
    for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto niter = node_map_.find((*iter)->id);
        if (niter != node_map_.end()) {
            node_map_.erase(niter);
        }
    }
}

void ElectPool::FtsGetNodes(
        uint32_t count,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::vector<NodeDetailPtr>& res_nodes) {
    common::FtsTree fts_tree;
    for (auto iter = src_nodes.begin(); iter != src_nodes.end(); ++iter) {
        fts_tree.AppendFtsNode((*iter)->choosed_balance, (void*)&(*iter));
    }

    fts_tree.CreateFtsTree();
    std::set<void*> tmp_res_nodes;
    fts_tree.GetNodes(vss::VssManager::Instance()->EpochRandom(), count, tmp_res_nodes);
    for (auto iter = tmp_res_nodes.begin(); iter != tmp_res_nodes.end(); ++iter) {
        res_nodes.push_back(*((NodeDetailPtr*)(*iter)));
    }
}

void ElectPool::GetAllValidNodes(
        uint64_t min_balance,
        uint64_t max_balance,
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes) {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        node_map = node_map_;
    }

    auto now_tm = std::chrono::steady_clock::now();
    auto now_hb_tm = (std::chrono::steady_clock::now().time_since_epoch().count()
        - (1000000000llu * 1800llu)) / (1000000000llu * 300llu);
    std::vector<NodeDetailPtr> choosed_nodes;
    for (auto iter = node_map.begin(); iter != node_map.end(); ++iter) {
        // for fts poise
        if (iter->second->choosed_balance < min_balance || iter->second->choosed_balance > max_balance) {
            continue;
        }

        auto valid_join_time = iter->second->join_tm +
            std::chrono::microseconds(kElectAvailableJoinTime);
        if (valid_join_time > now_tm) {
            continue;
        }

        uint32_t succ_hb_count = 0;
        uint32_t fail_hb_count = 0;
        std::lock_guard<std::mutex> guard(iter->second->heartbeat_mutex);
        for (auto hb_iter = iter->second->heatbeat_succ_count.begin();
                hb_iter != iter->second->heatbeat_succ_count.end();) {
            if (hb_iter->first < now_hb_tm) {
                iter->second->heatbeat_succ_count.erase(hb_iter++);
            } else {
                succ_hb_count += hb_iter->second;
            }
        }

        for (auto hb_iter = iter->second->heatbeat_fail_count.begin();
            hb_iter != iter->second->heatbeat_fail_count.end();) {
            if (hb_iter->first < now_hb_tm) {
                iter->second->heatbeat_fail_count.erase(hb_iter++);
            } else {
                fail_hb_count += hb_iter->second;
            }
        }

        if (succ_hb_count < 2 * fail_hb_count) {
            continue;
        }

        nodes_filter.Add(common::Hash::Hash64(iter->second->id));
        nodes.push_back(iter->second);
    }

    std::sort(nodes.begin(), nodes.end(), ElectNodeCompare);
}

void ElectPool::UpdateNodeHeartbeat() {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        node_map = node_map_;
    }

    auto now_tm = std::chrono::steady_clock::now().time_since_epoch().count() / (1000000000llu * 300llu);
    for (auto iter = node_map.begin(); iter != node_map.end(); ++iter) {
        bool reacheable = false;
        common::RemoteReachable(iter->second->public_ip, iter->second->public_port, &reacheable);
        if (reacheable) {
            std::lock_guard<std::mutex> guard(iter->second->heartbeat_mutex);
            ++iter->second->heatbeat_succ_count[now_tm];
            continue;
        }

        std::lock_guard<std::mutex> guard(iter->second->heartbeat_mutex);
        ++iter->second->heatbeat_fail_count[now_tm];
    }

    heartbeat_tick_.CutOff(
        5llu * 60llu * 10000000llu,
        std::bind(&ElectPool::UpdateNodeHeartbeat, this));
}

};  // namespace elect

};  //  namespace tenon
