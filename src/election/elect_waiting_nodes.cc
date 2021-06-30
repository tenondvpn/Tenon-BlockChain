#include "election/elect_waiting_nodes.h"

#include "common/hash.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "dht/base_dht.h"
#include "transport/proto/transport.pb.h"
#include "election/elect_pool_manager.h"
#include "election/elect_manager.h"
#include "election/proto/elect.pb.h"
#include "election/proto/elect_proto.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace elect {

ElectWaitingNodes::ElectWaitingNodes(uint32_t waiting_shard_id, ElectPoolManager* pool_manager)
    : waiting_shard_id_(waiting_shard_id), pool_manager_(pool_manager) {}

ElectWaitingNodes::~ElectWaitingNodes() {}

void ElectWaitingNodes::UpdateWaitingNodes(
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter) {
    std::lock_guard<std::mutex> guard(all_nodes_waiting_map_mutex_);
    std::string coming_id = root_node_id + std::to_string(
        tmblock::TimeBlockManager::Instance()->LatestTimestamp());
    if (coming_root_nodes_.find(coming_id) != coming_root_nodes_.end()) {
        return;
    }

    coming_root_nodes_.insert(coming_id);
    auto member_index = ElectManager::Instance()->GetMemberIndex(
        network::kRootCongressNetworkId,
        root_node_id);
    if (member_index == elect::kInvalidMemberIndex) {
        return;
    }

    std::sort(
        local_all_waiting_nodes_.begin(),
        local_all_waiting_nodes_.end(),
        ElectNodeIdCompare);
    WaitingListPtr wait_ptr = std::make_shared<WaitingList>();
    std::string all_nodes_ids;
    for (auto iter = local_all_waiting_nodes_.begin();
            iter != local_all_waiting_nodes_.end(); ++iter) {
        if (!nodes_filter.Contain(common::Hash::Hash64((*iter)->id))) {
            continue;
        }
        
        wait_ptr->nodes_vec.push_back(*iter);
        all_nodes_ids += (*iter)->id;
    }

    wait_ptr->nodes_hash = common::Hash::Hash64(all_nodes_ids);
    auto iter = all_nodes_waiting_map_.find(wait_ptr->nodes_hash);
    if (iter == all_nodes_waiting_map_.end()) {
        wait_ptr->same_root_count = 1;
        all_nodes_waiting_map_[wait_ptr->nodes_hash] = wait_ptr;
        std::cout << "UpdateWaitingNodes called: " << 1 << ", waiting_shard_id_: " << waiting_shard_id_ << std::endl;
    } else {
        ++iter->second->same_root_count;
        std::cout << "UpdateWaitingNodes called: " << iter->second->same_root_count << ", waiting_shard_id_: " << waiting_shard_id_ << std::endl;
    }
}

void ElectWaitingNodes::OnTimeBlock(uint64_t tm_block_tm) {
    std::cout << "ElectWaitingNodes::OnTimeBlock: " << tm_block_tm
        << ", waiting_shard_id_: " << waiting_shard_id_
        << ", got_valid_nodes_tm_: " << got_valid_nodes_tm_
        << std::endl;
    std::lock_guard<std::mutex> guard(all_nodes_waiting_map_mutex_);
    if (got_valid_nodes_tm_ >= tm_block_tm) {
        return;
    }

    GetThisTimeBlockLocallNodes(tm_block_tm);
    SendConsensusNodes(tm_block_tm);
    got_valid_nodes_tm_ = tm_block_tm;
}

void ElectWaitingNodes::GetThisTimeBlockLocallNodes(uint64_t tm_block_tm) {
    got_valid_nodes_tm_ = tm_block_tm;
    local_all_waiting_bloom_filter_ = common::BloomFilter(
        kBloomfilterWaitingSize,
        kBloomfilterWaitingHashCount);
    local_all_waiting_nodes_.clear();
    GetAllValidHeartbeatNodes(0, local_all_waiting_bloom_filter_, local_all_waiting_nodes_);
}

void ElectWaitingNodes::GetAllValidNodes(
        common::BloomFilter& nodes_filter,
        std::vector<NodeDetailPtr>& nodes) {
    std::vector<WaitingListPtr> waiting_nodes;
    {
        std::lock_guard<std::mutex> guard(all_nodes_waiting_map_mutex_);
        for (auto iter = all_nodes_waiting_map_.begin();
            iter != all_nodes_waiting_map_.end(); ++iter) {
            waiting_nodes.push_back(iter->second);
        }
    }

    if (waiting_nodes.empty()) {
        return;
    }

    std::sort(waiting_nodes.begin(), waiting_nodes.end(), WaitingNodeCountCompare);
    auto max_count_nodes = *(waiting_nodes.begin());
    for (auto iter = max_count_nodes->nodes_vec.begin();
            iter != max_count_nodes->nodes_vec.end(); ++iter) {
        nodes.push_back(*iter);
        nodes_filter.Add(common::Hash::Hash64((*iter)->id));
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
        std::cout << "valid_join_time: " << valid_join_time.time_since_epoch().count() << ", now_tm: " << now_tm.time_since_epoch().count() << std::endl;
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

void ElectWaitingNodes::HandleUpdateNodeHeartbeat(NodeDetailPtr& node_ptr) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    auto iter = node_map_.find(node_ptr->id);
    if (iter != node_map_.end()) {
        ++iter->second->heatbeat_succ_count[
            tmblock::TimeBlockManager::Instance()->LatestTimestamp()];
    } else {
        node_ptr->heatbeat_succ_count[
            tmblock::TimeBlockManager::Instance()->LatestTimestamp()] = 1;
        node_map_[node_ptr->id] = node_ptr;
    }
}

void ElectWaitingNodes::SendConsensusNodes(uint64_t time_block_tm) {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    last_send_tm_ = time_block_tm;
    GetAllValidHeartbeatNodes(0, local_all_waiting_bloom_filter_, local_all_waiting_nodes_);
    std::cout << "SendConsensusNodes called: " << time_block_tm 
        << ", waiting_shard_id_: " << waiting_shard_id_
        << ", local_all_waiting_nodes_.empty(): " << local_all_waiting_nodes_.empty()
        << std::endl;
    if (!local_all_waiting_nodes_.empty()) {
        transport::protobuf::Header msg;
        elect::ElectProto::CreateElectWaitingNodes(
            dht->local_node(),
            waiting_shard_id_,
            local_all_waiting_bloom_filter_,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
            std::cout << "SendConsensusNodes called: " << time_block_tm << ", waiting_shard_id_: " << waiting_shard_id_ << std::endl;
        }
    }
}

};  // namespace elect

};  // namespace tenon
