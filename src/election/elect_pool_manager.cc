#include "election/elect_pool_manager.h"

#include <functional>
#include <algorithm>
#include <random>

#include "common/fts_tree.h"
#include "common/random.h"
#include "bft/bft_utils.h"
#include "vss/vss_manager.h"
#include "security/secp256k1.h"
#include "security/schnorr.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "network/network_utils.h"

namespace tenon {

namespace elect {

ElectPoolManager::ElectPoolManager() {}

ElectPoolManager::~ElectPoolManager() {}

int ElectPoolManager::LeaderCreateElectionBlockTx(
        uint32_t shard_netid,
        bft::protobuf::BftMessage& bft_msg) {
    common::BloomFilter cons_all(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter cons_weed_out(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    common::BloomFilter pick_in(kBloomfilterSize, kBloomfilterHashCount);
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

    std::cout << "leader get all nodes" << std::endl;
    for (uint32_t i = 0; i < pick_in_vec.size(); ++i) {
        std::cout << common::Encode::HexEncode(pick_in_vec[i]->id) << std::endl;
    }
    std::cout << std::endl;

    bft::protobuf::TxBft tx_bft;
    auto tx_info = tx_bft.mutable_new_tx();
    tx_info->set_type(common::kConsensusRootElectShard);
    tx_info->set_from(common::GlobalInfo::Instance()->id());
    tx_info->set_gas_limit(0llu);
    tx_info->set_network_id(shard_netid);
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
    pick_in_attr->set_key(kElectNodeAttrKeyPickInBloomfilter);
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
    ec_block_attr->set_key(kElectNodeAttrElectBlock);
    ec_block_attr->set_value(ec_block.SerializeAsString());
    bft_msg.set_net_id(shard_netid);
    bft_msg.set_data(tx_bft.SerializeAsString());
    bft_msg.set_gid(common::CreateGID(""));
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_node_id(common::GlobalInfo::Instance()->id());
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto hash128 = bft::GetTxMessageHash(*tx_info);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign)) {
        return kElectError;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    return kElectSuccess;
}

int ElectPoolManager::BackupCheckElectionBlockTx(const bft::protobuf::TxInfo& tx_info) {
    common::BloomFilter leader_cons_all;
    common::BloomFilter leader_cons_weed_out;
    common::BloomFilter leader_pick_all;
    common::BloomFilter leader_pick_in;
    elect::protobuf::ElectBlock leader_ec_block;
    if (GetAllLeaderBloomFiler(
            tx_info,
            &leader_cons_all,
            &leader_cons_weed_out,
            &leader_pick_all,
            &leader_pick_in,
            &leader_ec_block) != kElectSuccess) {
        ELECT_ERROR("GetAllLeaderBloomFiler failed!");
        return kElectError;
    }

    common::BloomFilter cons_all(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter cons_weed_out(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    common::BloomFilter pick_in(kBloomfilterSize, kBloomfilterHashCount);
    std::vector<NodeDetailPtr> exists_shard_nodes;
    std::vector<NodeDetailPtr> weed_out_vec;
    std::vector<NodeDetailPtr> pick_in_vec;
    if (GetAllBloomFilerAndNodes(
            tx_info.network_id(),
            &cons_all,
            &cons_weed_out,
            &pick_all,
            &pick_in,
            exists_shard_nodes,
            weed_out_vec,
            pick_in_vec) != kElectSuccess) {
        ELECT_ERROR("local GetAllBloomFilerAndNodes failed!");
        return kElectError;
    }

    std::cout << "bakcup get all nodes" << std::endl;
    for (uint32_t i = 0; i < pick_in_vec.size(); ++i) {
        std::cout << common::Encode::HexEncode(pick_in_vec[i]->id) << std::endl;
    }
    std::cout << std::endl;

    // exists shard nodes must equal
    if (cons_all != leader_cons_all) {
        ELECT_ERROR("cons_all != leader_cons_all!");
        return kElectError;
    }

    if (cons_weed_out != leader_cons_weed_out) {
        ELECT_ERROR("cons_weed_out != leader_cons_weed_out!");
        return kElectError;
    }
    
    if (pick_all != leader_pick_all) {
        ELECT_ERROR("pick_all != leader_pick_all!");
        return kElectError;
    }

    if (pick_in != leader_pick_in) {
        ELECT_ERROR("pick_in != leader_pick_in");
        return kElectError;
    }

    std::set<std::string> weed_out_id_set;
    for (auto iter = weed_out_vec.begin(); iter != weed_out_vec.end(); ++iter) {
        weed_out_id_set.insert((*iter)->id);
    }

    if ((uint32_t)leader_ec_block.in_size() < exists_shard_nodes.size() - weed_out_id_set.size()) {
        ELECT_ERROR("leader_ec_block.in_size() error!");
        return kElectError;
    }

    uint32_t leader_idx = 0;
    for (auto iter = exists_shard_nodes.begin(); iter != exists_shard_nodes.end(); ++iter) {
        if (weed_out_id_set.find((*iter)->id) != weed_out_id_set.end()) {
            continue;
        }

        if (leader_ec_block.in(leader_idx).pubkey() != (*iter)->public_key) {
            ELECT_ERROR("leader_ec_block public key not equal local public key error!");
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).dht_key() != (*iter)->dht_key) {
            ELECT_ERROR("leader_ec_block dht key not equal local dht key error!");
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).public_ip() != (*iter)->public_ip) {
            ELECT_ERROR("leader_ec_block public_ip not equal local public_ip error!");
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).public_port() != (*iter)->public_port) {
            ELECT_ERROR("leader_ec_block public_port not equal local public_port error!");
            return kElectError;
        }

        ++leader_idx;
    }

    for (int32_t i = leader_idx; i < leader_ec_block.in_size(); ++i) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(
            leader_ec_block.in(leader_idx).pubkey());
        if (!leader_pick_in.Contain(common::Hash::Hash64(id))) {
            ELECT_ERROR("leader_pick_in.Contain error!");
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

    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(network_id);
        if (iter == waiting_pool_map_.end()) {
            waiting_pool_ptr = std::make_shared<ElectWaitingNodes>(network_id, this);
            waiting_pool_map_[network_id] = waiting_pool_ptr;
        } else {
            waiting_pool_ptr = iter->second;
        }
    }

    waiting_pool_ptr->AddNewNode(node_ptr);
}

void ElectPoolManager::GetAllWaitingNodes(
        uint64_t time_offset_milli,
        uint32_t waiting_shard_id,
        common::BloomFilter* pick_all,
        std::vector<NodeDetailPtr>& nodes) {
    if (waiting_shard_id < network::kConsensusWaitingShardBeginNetworkId ||
            waiting_shard_id >= network::kConsensusWaitingShardEndNetworkId) {
        return;
    }

    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(waiting_shard_id);
        if (iter == waiting_pool_map_.end()) {
            return;
        }
      
        waiting_pool_ptr = iter->second;
    }

    waiting_pool_ptr->GetAllValidHeartbeatNodes(time_offset_milli, *pick_all, nodes);
}

void ElectPoolManager::UpdateWaitingNodes(
        uint32_t waiting_shard_id,
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter) {
    if (waiting_shard_id < network::kConsensusWaitingShardBeginNetworkId ||
        waiting_shard_id >= network::kConsensusWaitingShardEndNetworkId) {
        return;
    }

    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(waiting_shard_id);
        if (iter == waiting_pool_map_.end()) {
            return;
        }

        waiting_pool_ptr = iter->second;
    }

    waiting_pool_ptr->UpdateWaitingNodes(root_node_id, nodes_filter);
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
    uint64_t min_balance = 0;
    uint64_t max_balance = 0;
    consensus_pool_ptr->GetAllValidNodes(*cons_all, exists_shard_nodes);
    uint32_t weed_out_count = exists_shard_nodes.size() / kFtsWeedoutDividRate;
    FtsGetNodes(
        true,
        weed_out_count,
        cons_weed_out,
        exists_shard_nodes,
        weed_out_vec);
    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(shard_netid + network::kConsensusWaitingShardOffset);
        if (iter == waiting_pool_map_.end()) {
            ELECT_ERROR("find waiting shard network failed [%u]!",
                shard_netid + network::kConsensusWaitingShardOffset);
            return kElectError;
        }

        waiting_pool_ptr = iter->second;
    }

    std::vector<NodeDetailPtr> pick_all_vec;
    waiting_pool_ptr->GetAllValidNodes(*pick_all, pick_all_vec);
    if (pick_all_vec.empty()) {
        return kElectSuccess;
    }

    std::cout << "all waiting nodes: " << std::endl;
    for (uint32_t i = 0; i < pick_all_vec.size(); ++i) {
        std::cout << common::Encode::HexEncode(pick_all_vec[i]->id) << std::endl;
    }
    std::cout << std::endl << std::endl;

    FtsGetNodes(
        false,
        weed_out_count,
        pick_in,
        pick_all_vec,
        pick_in_vec);
    std::cout << "get pick_in_vec size: " << pick_in_vec.size() << std::endl;
    return kElectSuccess;
}

void ElectPoolManager::FtsGetNodes(
        bool weed_out,
        uint32_t count,
        common::BloomFilter* nodes_filter,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::vector<NodeDetailPtr>& res_nodes) {
    auto sort_vec = src_nodes;
    std::mt19937_64 g2(vss::VssManager::Instance()->EpochRandom());
    SmoothFtsValue((src_nodes.size() - (src_nodes.size() / 3)), g2, sort_vec);
    std::set<void*> tmp_res_nodes;
    std::cout << "FtsGetNodes: " << std::endl;
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
        std::cout << "choose rand value: ";
        void* data = fts_tree.GetOneNode(g2);
        std::cout << std::endl;
        if (data == nullptr) {
            continue;
        }

        tmp_res_nodes.insert(data);
        NodeDetailPtr node_ptr = *((NodeDetailPtr*)data);
        res_nodes.push_back(node_ptr);
        nodes_filter->Add(common::Hash::Hash64(node_ptr->id));
    }

    std::cout << std::endl;
}

void ElectPoolManager::SmoothFtsValue(
        int32_t count,
        std::mt19937_64& g2,
        std::vector<NodeDetailPtr>& sort_vec) {
    assert(sort_vec.size() > (uint32_t)count);
    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceCompare);
    for (uint32_t i = 1; i < sort_vec.size(); ++i) {
        sort_vec[i]->balance_diff = sort_vec[i]->choosed_balance - sort_vec[i - 1]->choosed_balance;
    }

    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceDiffCompare);
    uint64_t diff_2b3 = sort_vec[sort_vec.size() * 2 / 3]->balance_diff;
    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceCompare);
    sort_vec[0]->fts_value = 100llu;  // diff with default node fts value 0
    for (uint32_t i = 1; i < sort_vec.size(); ++i) {
        uint64_t fts_val_diff = sort_vec[i]->choosed_balance - sort_vec[i - 1]->choosed_balance;
        if (fts_val_diff < diff_2b3) {
            auto rand_val = fts_val_diff + g2() % (diff_2b3 - fts_val_diff);
            sort_vec[i]->fts_value = sort_vec[i - 1]->fts_value + (20 * rand_val) / diff_2b3;
            std::cout << "0: " << i << ":" << sort_vec[i]->fts_value << ":" << rand_val << ":" << diff_2b3 << ":" << fts_val_diff << std::endl;
        } else {
            auto rand_val = diff_2b3 + g2() % (fts_val_diff + 1 - diff_2b3);
            sort_vec[i]->fts_value = sort_vec[i - 1]->fts_value + (20 * rand_val) / fts_val_diff;
            std::cout << "1: " << i << ":" << sort_vec[i]->fts_value << ":" << rand_val << ":" << diff_2b3 << ":" << fts_val_diff << std::endl;
        }
    }
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

        if (tx_info.attr(i).key() == kElectNodeAttrKeyPickInBloomfilter) {
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
        std::string pubkey_str;
        (*iter)->pubkey.Serialize(pubkey_str);
        elect_node->public_key = pubkey_str;
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
