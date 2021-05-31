#include "election/elect_pool_manager.h"

#include <functional>

#include "subscript/subs_consensus.h"

namespace tenon {

namespace elect {

ElectPoolManager::ElectPoolManager() {
    subs::SubsConsensus::Instance()->AddCallback(std::bind(
        &ElectPoolManager::UpdateNodeInfoWithBlock,
        this,
        std::placeholders::_1));
}

ElectPoolManager::~ElectPoolManager() {}

// elect block coming
void ElectPoolManager::NetworkMemberChange(uint32_t network_id, MembersPtr& members_ptr) {
    ElectPoolPtr pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
        auto iter = elect_pool_map_.find(network_id);
        if (iter == elect_pool_map_.end()) {
            pool_ptr = std::make_shared<ElectPool>();
            elect_pool_map_[network_id] = pool_ptr;
        } else {
            pool_ptr = iter->second;
        }
    }

    for (auto iter = members_ptr->begin(); iter != members_ptr->end(); ++iter) {
        auto elect_node = std::make_shared<ElectNodeDetail>();
        elect_node->id = (*iter)->id;
        elect_node->public_ip = (*iter)->public_ip;
        elect_node->public_port = (*iter)->public_port;
        elect_node->dht_key = (*iter)->dht_key;
        pool_ptr->AddNewNode(elect_node);
        {
            std::lock_guard<std::mutex> guard(node_ip_set_mutex_);
            node_ip_set_.insert(common::IpStringToUint32(elect_node->public_ip));
        }

        std::lock_guard<std::mutex> guard(all_node_map_mutex_);
        all_node_map_[elect_node->id] = elect_node;
    }
}

void ElectPoolManager::UpdateNodeInfoWithBlock(const bft::protobuf::Block& block_info) {
    // (TODO): verify agg sign
    const auto& tx_list = block_info.tx_list();
    if (tx_list.empty()) {
        ELECT_ERROR("tx block tx list is empty.");
        return;
    }
    
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        std::string account_id;
        if (tx_list[i].to_add()) {
            account_id = tx_list[i].to();
        } else {
            account_id = tx_list[i].from();
        }

        // update balance for fts
        std::lock_guard<std::mutex> guard(all_node_map_mutex_);
        auto iter = all_node_map_.find(account_id);
        if (iter != all_node_map_.end()) {
            std::lock_guard<std::mutex> guard2(iter->second->height_with_balance_mutex);
            iter->second->height_with_balance[block_info.height()] = tx_list[i].balance();
            if (iter->second->height_with_balance.size() > 9) {
                // map sort with height
                iter->second->height_with_balance.erase(iter->second->height_with_balance.begin());
            }
        }
    }
}

};  // namespace elect

};  //  namespace tenon
