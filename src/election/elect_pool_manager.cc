#include "election/elect_pool_manager.h"

#include <functional>

#include "security/secp256k1.h"
#include "network/network_utils.h"

namespace tenon {

namespace elect {

ElectPoolManager::ElectPoolManager() {}

ElectPoolManager::~ElectPoolManager() {}

int ElectPoolManager::LeaderCreateElectionBlockTx(
        uint32_t shard_netid,
        bft::protobuf::BftMessage& bft_msg) {
    common::BloomFilter cons_all;
    common::BloomFilter cons_weed_out;
    common::BloomFilter pick_all;
    common::BloomFilter pick_in;
    std::vector<NodeDetailPtr> exists_shard_nodes;
    std::vector<NodeDetailPtr> weed_out_vec;
    std::vector<NodeDetailPtr> pick_in_vec;
    if (GetAllBloomFilerAndNodes(
            shard_netid,
            &cons_all,
            &cons_weed_out,
            &pick_all,
            &pick_in,
            exists_shard_nodes,
            weed_out_vec,
            pick_in_vec) != kElectSuccess) {
        ELECT_ERROR("GetAllBloomFilerAndNodes failed!");
        return kElectError;
    }

    bft::protobuf::TxBft tx_bft;
    auto tx_info = tx_bft.mutable_new_tx();
    tx_info->set_from(common::GlobalInfo::Instance()->id());
    tx_info->set_gas_limit(0llu);
    auto all_exits_attr = tx_info->add_attr();
    all_exits_attr->set_key(kElectNodeAttrKeyAllBloomfilter);
    all_exits_attr->set_value(cons_all.Serialize());
    auto weed_out_attr = tx_info->add_attr();
    weed_out_attr->set_key(kElectNodeAttrKeyWeedoutBloomfilter);
    weed_out_attr->set_value(cons_weed_out.Serialize());
    auto all_pick_attr = tx_info->add_attr();
    all_pick_attr->set_key(kElectNodeAttrKeyAllPickBloomfilter);
    all_pick_attr->set_value(pick_all.Serialize());
    auto pick_in_attr = tx_info->add_attr();
    pick_in_attr->set_key(kElectNodeAttrKeyAllPickInBloomfilter);
    pick_in_attr->set_value(pick_in.Serialize());
    std::set<std::string> weed_out_id_set;
    for (auto iter = weed_out_vec.begin(); iter != weed_out_vec.end(); ++iter) {
        weed_out_id_set.insert((*iter)->id);
    }

    elect::protobuf::ElectBlock ec_block;
    for (auto iter = exists_shard_nodes.begin(); iter != exists_shard_nodes.end(); ++iter) {
        if (weed_out_id_set.find((*iter)->id) != weed_out_id_set.end()) {
            continue;
        }

        auto in = ec_block.add_in();
        in->set_pubkey((*iter)->public_key);
        in->set_dht_key((*iter)->dht_key);
        in->set_public_ip((*iter)->public_ip);
        in->set_public_port((*iter)->public_port);
    }

    for (auto iter = pick_in_vec.begin(); iter != pick_in_vec.end(); ++iter) {
        auto in = ec_block.add_in();
        in->set_pubkey((*iter)->public_key);
        in->set_dht_key((*iter)->dht_key);
        in->set_public_ip((*iter)->public_ip);
        in->set_public_port((*iter)->public_port);
    }

    auto ec_block_attr = tx_info->add_attr();
    pick_in_attr->set_key(kElectNodeAttrElectBlock);
    pick_in_attr->set_value(ec_block.SerializeAsString());
    bft_msg.set_net_id(shard_netid);
    bft_msg.set_data(tx_bft.SerializeAsString());
    return kElectSuccess;
}

int ElectPoolManager::BackupCheckElectionBlockTx(const bft::protobuf::BftMessage& bft_msg) {
    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        return kElectError;
    }

    common::BloomFilter leader_cons_all;
    common::BloomFilter leader_cons_weed_out;
    common::BloomFilter leader_pick_all;
    common::BloomFilter leader_pick_in;
    elect::protobuf::ElectBlock leader_ec_block;
    if (GetAllLeaderBloomFiler(
            tx_bft.new_tx(),
            &leader_cons_all,
            &leader_cons_weed_out,
            &leader_pick_all,
            &leader_pick_in,
            &leader_ec_block) != kElectSuccess) {
        return kElectError;
    }

    common::BloomFilter cons_all;
    common::BloomFilter cons_weed_out;
    common::BloomFilter pick_all;
    common::BloomFilter pick_in;
    std::vector<NodeDetailPtr> exists_shard_nodes;
    std::vector<NodeDetailPtr> weed_out_vec;
    std::vector<NodeDetailPtr> pick_in_vec;
    if (GetAllBloomFilerAndNodes(
            bft_msg.net_id(),
            &cons_all,
            &cons_weed_out,
            &pick_all,
            &pick_in,
            exists_shard_nodes,
            weed_out_vec,
            pick_in_vec) != kElectSuccess) {
        return kElectError;
    }

    // exists shard nodes must equal
    if (cons_all != leader_cons_all) {
        return kElectError;
    }

    if (cons_weed_out.DiffCount(leader_cons_weed_out) * (100 / kTolerateLeaderBackupFiffRate) >
            cons_weed_out.valid_count()) {
        return kElectError;
    }
    
    if (pick_all.DiffCount(leader_pick_all) * (100 / kTolerateLeaderBackupFiffRate) >
            pick_all.valid_count()) {
        return kElectError;
    }

    if (pick_in.DiffCount(leader_pick_in) * (100 / kTolerateLeaderBackupFiffRate) >
            pick_in.valid_count()) {
        return kElectError;
    }

    std::set<std::string> weed_out_id_set;
    for (auto iter = weed_out_vec.begin(); iter != weed_out_vec.end(); ++iter) {
        weed_out_id_set.insert((*iter)->id);
    }

    if (leader_ec_block.in_size() < exists_shard_nodes.size() - weed_out_id_set.size()) {
        return kElectError;
    }

    uint32_t leader_idx = 0;
    for (auto iter = exists_shard_nodes.begin(); iter != exists_shard_nodes.end(); ++iter) {
        if (weed_out_id_set.find((*iter)->id) != weed_out_id_set.end()) {
            continue;
        }

        if (leader_ec_block.in(leader_idx).pubkey() != (*iter)->public_key) {
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).dht_key() != (*iter)->dht_key) {
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).public_ip() != (*iter)->public_ip) {
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).public_port() != (*iter)->public_port) {
            return kElectError;
        }

        ++leader_idx;
    }

    for (uint32_t i = leader_idx; i < leader_ec_block.in_size(); ++i) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(
            leader_ec_block.in(leader_idx).pubkey());
        if (!leader_pick_in.Contain(common::Hash::Hash64(id))) {
            return kElectError;
        }
    }

    return kElectSuccess;
}

void ElectPoolManager::AddWaitingPoolNode(uint32_t network_id, NodeDetailPtr& node_ptr) {
    if (network_id < network::kConsensusWaitingShardBeginNetworkId ||
            network_id >= network::kConsensusWaitingShardEndNetworkId) {
        return;
    }

    ElectPoolPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
        auto iter = elect_pool_map_.find(network_id);
        if (iter == elect_pool_map_.end()) {
            waiting_pool_ptr = std::make_shared<ElectPool>();
            elect_pool_map_[network_id] = waiting_pool_ptr;
        } else {
            waiting_pool_ptr = iter->second;
        }
    }

    waiting_pool_ptr->AddNewNode(node_ptr);
}

int ElectPoolManager::GetAllBloomFilerAndNodes(
        uint32_t shard_netid,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        std::vector<NodeDetailPtr>& exists_shard_nodes,
        std::vector<NodeDetailPtr>& weed_out_vec,
        std::vector<NodeDetailPtr>& pick_in_vec) {
    ElectPoolPtr consensus_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
        auto iter = elect_pool_map_.find(shard_netid);
        if (iter == elect_pool_map_.end()) {
            ELECT_ERROR("find shard network failed [%u]!", shard_netid);
            return kElectError;
        }

        consensus_pool_ptr = iter->second;
    }

    // get consensus shard nodes and weed out nodes
    common::BloomFilter exits_filters(kBloomfilterSize, kBloomfilterHashCount);
    uint64_t min_balance = 0;
    uint64_t max_balance = 0;
    consensus_pool_ptr->GetAllValidNodes(exits_filters, exists_shard_nodes);
    uint32_t weed_out_count = exists_shard_nodes.size() / kFtsWeedoutDividRate;
    common::BloomFilter weed_out_filters(kBloomfilterSize, kBloomfilterHashCount);
    consensus_pool_ptr->FtsGetNodes(
        true,
        weed_out_count,
        weed_out_filters,
        exists_shard_nodes,
        weed_out_vec);
    ElectPoolPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
        auto iter = elect_pool_map_.find(shard_netid + network::kConsensusWaitingShardOffset);
        if (iter == elect_pool_map_.end()) {
            ELECT_ERROR("find waiting shard network failed [%u]!",
                shard_netid + network::kConsensusWaitingShardOffset);
            return kElectError;
        }

        waiting_pool_ptr = iter->second;
    }

    common::BloomFilter pick_all_filters(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    std::vector<NodeDetailPtr> pick_all_vec;
    waiting_pool_ptr->GetAllValidNodes(pick_all_filters, pick_all_vec);
    common::BloomFilter pick_in_filters(kBloomfilterSize, kBloomfilterHashCount);
    waiting_pool_ptr->FtsGetNodes(
        false,
        weed_out_count,
        pick_in_filters,
        pick_all_vec,
        pick_in_vec);
    return kElectSuccess;
}

int ElectPoolManager::GetAllLeaderBloomFiler(
        const bft::protobuf::TxInfo& tx_info,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        elect::protobuf::ElectBlock* ec_block) {
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == kElectNodeAttrKeyAllBloomfilter) {
            if (tx_info.attr(i).value().size() != kBloomfilterSize / 8) {
                return kElectError;
            }

            cons_all->Deserialize(
                (uint64_t*)tx_info.attr(i).value().c_str(),
                tx_info.attr(i).value().size() / sizeof(uint64_t),
                kBloomfilterHashCount);
        }

        if (tx_info.attr(i).key() == kElectNodeAttrKeyWeedoutBloomfilter) {
            if (tx_info.attr(i).value().size() != kBloomfilterSize / 8) {
                return kElectError;
            }

            cons_weed_out->Deserialize(
                (uint64_t*)tx_info.attr(i).value().c_str(),
                tx_info.attr(i).value().size() / sizeof(uint64_t),
                kBloomfilterHashCount);
        }

        if (tx_info.attr(i).key() == kElectNodeAttrKeyAllPickBloomfilter) {
            if (tx_info.attr(i).value().size() != kBloomfilterWaitingSize / 8) {
                return kElectError;
            }

            pick_all->Deserialize(
                (uint64_t*)tx_info.attr(i).value().c_str(),
                tx_info.attr(i).value().size() / sizeof(uint64_t),
                kBloomfilterWaitingHashCount);
        }

        if (tx_info.attr(i).key() == kElectNodeAttrKeyAllPickInBloomfilter) {
            if (tx_info.attr(i).value().size() != kBloomfilterSize / 8) {
                return kElectError;
            }

            pick_in->Deserialize(
                (uint64_t*)tx_info.attr(i).value().c_str(),
                tx_info.attr(i).value().size() / sizeof(uint64_t),
                kBloomfilterHashCount);
        }

        if (tx_info.attr(i).key() == kElectNodeAttrElectBlock) {
            if (!ec_block->ParseFromString(tx_info.attr(i).value())) {
                return kElectError;
            }
        }
    }

    return kElectSuccess;
}
// elect block coming
void ElectPoolManager::NetworkMemberChange(uint32_t network_id, MembersPtr& members_ptr) {
    ElectPoolPtr pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
        auto iter = elect_pool_map_.find(network_id);
        if (iter == elect_pool_map_.end()) {
            pool_ptr = std::make_shared<ElectPool>(network_id);
            elect_pool_map_[network_id] = pool_ptr;
        } else {
            pool_ptr = iter->second;
        }
    }

    std::vector<NodeDetailPtr> node_vec;
    for (auto iter = members_ptr->begin(); iter != members_ptr->end(); ++iter) {
        auto elect_node = std::make_shared<ElectNodeDetail>();
        elect_node->id = (*iter)->id;
        elect_node->public_ip = (*iter)->public_ip;
        elect_node->public_port = (*iter)->public_port;
        elect_node->dht_key = (*iter)->dht_key;
        node_vec.push_back(elect_node);
        {
            std::lock_guard<std::mutex> guard(node_ip_set_mutex_);
            node_ip_set_.insert(common::IpStringToUint32(elect_node->public_ip));
        }

        std::lock_guard<std::mutex> guard(all_node_map_mutex_);
        all_node_map_[elect_node->id] = elect_node;
    }

    pool_ptr->ReplaceWithElectNodes(node_vec);
}

// leader get all node balance block and broadcast to all root and waiting root
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
            // use map order
            if (!iter->second->height_with_balance.empty()) {
                iter->second->choosed_height = iter->second->height_with_balance.rbegin()->first;
                iter->second->choosed_balance = iter->second->height_with_balance.rbegin()->second;
            }

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
