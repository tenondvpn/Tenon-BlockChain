#include "election/elect_pool.h"

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

void ElectPool::FtsGetNodes(uint32_t count, std::vector<NodeDetailPtr>& nodes) {

}

void ElectPool::UpdateNodeHeartbeat() {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        node_map = node_map_;
    }

    for (auto iter = node_map.begin(); iter != node_map.end(); ++iter) {
        bool reacheable = false;
        common::RemoteReachable(iter->second->public_ip, iter->second->public_port, &reacheable);
        if (reacheable) {
            ++iter->second->heartbeat_success_count;
            continue;
        }

        ++iter->second->heartbeat_fail_count;
    }

    heartbeat_tick_.CutOff(
        30llu * 60llu * 10000000llu,
        std::bind(&ElectPool::UpdateNodeHeartbeat, this));
}

};  // namespace elect

};  //  namespace tenon
