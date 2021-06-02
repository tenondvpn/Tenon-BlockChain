#include "election/elect_waiting_nodes.h"

#include "common/hash.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "dht/base_dht.h"
#include "transport/proto/transport.pb.h"
#include "election/elect_pool_manager.h"
#include "election/member_manager.h"
#include "election/proto/elect.pb.h"
#include "election/proto/elect_proto.h"

namespace tenon {

namespace elect {

ElectWaitingNodes::ElectWaitingNodes(uint32_t waiting_shard_id, ElectPoolManager* pool_manager)
    : waiting_shard_id_(waiting_shard_id), pool_manager_(pool_manager) {
    heartbeat_tick_.CutOff(
        60llu * 10000000llu,
        std::bind(&ElectWaitingNodes::UpdateNodeHeartbeat, this));
    heartbeat_tick_.CutOff(
        60llu * 10000000llu,
        std::bind(&ElectWaitingNodes::SendConsensusNodes, this));
}

ElectWaitingNodes::~ElectWaitingNodes() {}

void ElectWaitingNodes::UpdateWaitingNodes(
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter) {
    auto member_index = MemberManager::Instance()->GetMemberIndex(
        waiting_shard_id_ - network::kConsensusWaitingShardOffset,
        root_node_id);
    if (member_index == elect::kInvalidMemberIndex) {
        return;
    }

    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    std::vector<NodeDetailPtr> nodes;
    pool_manager_->GetAllWaitingNodes(
        kWaitingNodesGetTimeoffsetMilli,
        waiting_shard_id_,
        &pick_all,
        nodes);
    std::cout << "UpdateWaitingNodes: " << nodes.empty() << std::endl;
    if (nodes.empty()) {
        return;
    }

    for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
        if (!nodes_filter.Contain(common::Hash::Hash64((*iter)->id))) {
            continue;
        }
        
        std::lock_guard<std::mutex> gaurd(consensus_waiting_count_mutex_);
        auto count_iter = consensus_waiting_count_.find((*iter)->id);
        if (count_iter == consensus_waiting_count_.end()) {
            {
                std::lock_guard<std::mutex> set_gaurd((*iter)->valid_node_set_mutex);
                (*iter)->valid_node_set.insert(root_node_id);
            }

            consensus_waiting_count_[(*iter)->id] = *iter;
            continue;
        }

        {
            std::lock_guard<std::mutex> set_gaurd(count_iter->second->valid_node_set_mutex);
            count_iter->second->valid_node_set.insert(root_node_id);
        }
    }
}

void ElectWaitingNodes::NewElectBlockClear() {
    std::lock_guard<std::mutex> gaurd(consensus_waiting_count_mutex_);
    consensus_waiting_count_.clear();
}

void ElectWaitingNodes::GetAllValidNodes(
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes) {
    uint32_t member_count = MemberManager::Instance()->GetMemberCount(
        waiting_shard_id_ - network::kConsensusWaitingShardOffset);
    uint32_t valid_count = (member_count * 2 / 3 + 1);
    for (auto iter = consensus_waiting_count_.begin();
            iter != consensus_waiting_count_.end(); ++iter) {
        std::lock_guard<std::mutex> gaurd(iter->second->valid_node_set_mutex);
        std::cout << "iter->second->valid_node_set.size(): " << iter->second->valid_node_set.size() << ":" << valid_count << std::endl;
        if (iter->second->valid_node_set.size() >= valid_count) {
            nodes.push_back(iter->second);
            nodes_filter.Add(common::Hash::Hash64(iter->second->id));
        }
    }

    std::sort(nodes.begin(), nodes.end(), ElectNodeIdCompare);
}

void ElectWaitingNodes::AddNewNode(NodeDetailPtr& node_ptr) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    node_map_[node_ptr->id] = node_ptr;
}

void ElectWaitingNodes::RemoveNodes(const std::vector<NodeDetailPtr>& nodes) {
    for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto niter = node_map_.find((*iter)->id);
        if (niter != node_map_.end()) {
            node_map_.erase(niter);
        }
    }
}

void ElectWaitingNodes::GetAllValidHeartbeatNodes(
        uint64_t time_offset_milli,
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes) {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        node_map = node_map_;
    }

    auto now_tm = std::chrono::steady_clock::now();
    auto now_hb_tm = (std::chrono::steady_clock::now().time_since_epoch().count()
        - (1000000000llu * 1800llu)) / (1000000000llu * 300llu);
    std::vector<NodeDetailPtr> choosed_nodes;
    for (auto iter = node_map.begin(); iter != node_map.end(); ++iter) {
        // for fts poise
        if (time_offset_milli * 1000 > kElectAvailableJoinTime) {
            time_offset_milli = kElectAvailableJoinTime / 1000;
        }

        auto valid_join_time = iter->second->join_tm +
            std::chrono::microseconds(kElectAvailableJoinTime - time_offset_milli * 1000);
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
}

void ElectWaitingNodes::UpdateNodeHeartbeat() {
    std::unordered_map<std::string, NodeDetailPtr> node_map;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        node_map = node_map_;
    }

    auto now_tm = std::chrono::steady_clock::now().time_since_epoch().count() /
        (1000000000llu * 300llu);
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
        60llu * 10000000llu,
        std::bind(&ElectWaitingNodes::UpdateNodeHeartbeat, this));
}

void ElectWaitingNodes::SendConsensusNodes() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        assert(false);
        return;
    }

    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    std::vector<NodeDetailPtr> pick_all_vec;
    GetAllValidHeartbeatNodes(0, pick_all, pick_all_vec);
    if (!pick_all_vec.empty()) {
        elect::ElectProto::CreateElectWaitingNodes(
            dht->local_node(),
            waiting_shard_id_,
            pick_all,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
        }
    }
    
    waiting_nodes_tick_.CutOff(
        60llu * 10000000llu,
        std::bind(&ElectWaitingNodes::SendConsensusNodes, this));
}

};  // namespace elect

};  // namespace tenon