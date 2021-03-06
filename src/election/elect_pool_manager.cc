#include "election/elect_pool_manager.h"

#include <functional>
#include <algorithm>
#include <random>

#include "bls/bls_manager.h"
#include "bft/bft_utils.h"
#include "common/fts_tree.h"
#include "common/random.h"
#include "election/elect_manager.h"
#include "election/nodes_stoke_manager.h"
#include "network/network_utils.h"
#include "security/secp256k1.h"
#include "security/security.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace elect {

static const std::string kElectGidPrefix = common::Encode::HexDecode("fc04c804d4049808ae33755fe9ae5acd50248f249a3ca8aea74fbea679274a11");
ElectPoolManager::ElectPoolManager() {
    update_stoke_tick_.CutOff(30000000l, std::bind(&ElectPoolManager::UpdateNodesStoke, this));
}

ElectPoolManager::~ElectPoolManager() {}

int ElectPoolManager::CreateElectTransaction(
        uint32_t shard_netid,
        uint64_t final_statistic_block_height,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info) {
    bool statistic_valid = false;
    std::string tm_str;
    for (int32_t i = 0; i < src_tx_info.attr_size(); ++i) {
        if (src_tx_info.attr(i).key() == tmblock::kAttrTimerBlockHeight) {
            tx_info.set_gid(common::Hash::Hash256(
                kElectGidPrefix +
                "_" +
                std::to_string(shard_netid) +
                "_" +
                std::to_string(final_statistic_block_height) +
                "_" +
                src_tx_info.attr(i).value()));
            tm_str = src_tx_info.attr(i).value();
        }
    }

    if (tx_info.gid().empty()) {
        ELECT_ERROR("CreateElectTransaction gid error shard id: %u", shard_netid);
        return kElectError;
    }

    if (src_tx_info.storages_size() != 1) {
        BFT_ERROR("tx info storage error[%d]", tx_info.storages_size());
        return kElectError;
    }

    if (src_tx_info.storages(0).key() != bft::kStatisticAttr) {
        BFT_ERROR("tx info storage key error[%s]", bft::kStatisticAttr.c_str());
        return kElectError;
    }

    block::protobuf::StatisticInfo statistic_info;
    if (!statistic_info.ParseFromString(src_tx_info.storages(0).value())) {
        return kElectError;
    }

    auto st_attr = tx_info.add_attr();
    st_attr->set_key(bft::kStatisticAttr);
    st_attr->set_value(src_tx_info.storages(0).value());
    tx_info.set_type(common::kConsensusRootElectShard);
    tx_info.set_from(common::kRootChainElectionBlockTxAddress);
    tx_info.set_gas_limit(0llu);
    tx_info.set_amount(0);
    tx_info.set_network_id(shard_netid);
    tx_info.set_version(common::kTransactionVersion);
    tx_info.set_amount(0);
    tx_info.set_gas_limit(0);
    tx_info.set_gas_used(0);
    tx_info.set_gas_price(common::kBuildinTransactionGasPrice);
    tx_info.set_balance(0);
    tx_info.set_status(bft::kBftSuccess);
    ELECT_INFO("CreateElectTransaction success gid: %s, shard id: %u, "
        "final_statistic_block_height: %lu, attr_tm: %s",
        common::Encode::HexEncode(tx_info.gid()).c_str(),
        shard_netid, final_statistic_block_height, tm_str.c_str());
    return kElectSuccess;
}

void ElectPoolManager::OnNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block) {
    node_credit_.OnNewElectBlock(height, elect_block);
}

int ElectPoolManager::GetElectionTxInfo(bft::protobuf::TxInfo& tx_info) {
    block::protobuf::StatisticInfo statistic_info;
    bool statistic_valid = false;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == bft::kStatisticAttr) {
            if (!statistic_info.ParseFromString(tx_info.attr(i).value())) {
                return kElectError;
            }

            statistic_valid = true;
        }
    }

    if (!statistic_valid) {
        return kElectError;
    }

    common::BloomFilter cons_all(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter cons_weed_out(kBloomfilterSize, kBloomfilterHashCount);
    common::BloomFilter pick_all(kBloomfilterWaitingSize, kBloomfilterWaitingHashCount);
    common::BloomFilter pick_in(kBloomfilterSize, kBloomfilterHashCount);
    int32_t leader_count = 0;
    std::vector<NodeDetailPtr> elected_nodes;
    std::set<std::string> weed_out_ids;
    if (GetAllBloomFilerAndNodes(
            statistic_info,
            tx_info.network_id(),
            &cons_all,
            &cons_weed_out,
            &pick_all,
            &pick_in,
            elected_nodes,
            weed_out_ids) != kElectSuccess) {
        ELECT_ERROR("GetAllBloomFilerAndNodes failed!");
        return kElectError;
    }

    auto all_exits_attr = tx_info.add_attr();
    all_exits_attr->set_key(kElectNodeAttrKeyAllBloomfilter);
    all_exits_attr->set_value(cons_all.Serialize());
    auto weed_out_attr = tx_info.add_attr();
    weed_out_attr->set_key(kElectNodeAttrKeyWeedoutBloomfilter);
    weed_out_attr->set_value(cons_weed_out.Serialize());
    auto all_pick_attr = tx_info.add_attr();
    all_pick_attr->set_key(kElectNodeAttrKeyAllPickBloomfilter);
    all_pick_attr->set_value(pick_all.Serialize());
    auto pick_in_attr = tx_info.add_attr();
    pick_in_attr->set_key(kElectNodeAttrKeyPickInBloomfilter);
    pick_in_attr->set_value(pick_in.Serialize());
    elect::protobuf::ElectBlock ec_block;
    int32_t idx = 0;
    for (auto iter = elected_nodes.begin(); iter != elected_nodes.end(); ++iter) {
        auto in = ec_block.add_in();
        in->set_pubkey((*iter)->public_key);
        in->set_pool_idx_mod_num((*iter)->init_pool_index_mod_num);
        in->set_public_ip((*iter)->public_ip & ip::Netmask(common::kNodePublicIpMaskLen));
    }

    ec_block.set_shard_network_id(tx_info.network_id());
    common::Bitmap bitmap;
    if (bls::BlsManager::Instance()->AddBlsConsensusInfo(ec_block, &bitmap) == bls::kBlsSuccess) {
        if (SelectLeader(tx_info.network_id(), bitmap, &ec_block) != kElectSuccess) {
            BLS_ERROR("SelectLeader info failed!");
            return kElectError;
        }
    }
    
    for (auto iter = weed_out_ids.begin(); iter != weed_out_ids.end(); ++iter) {
        ec_block.add_weedout_ids(*iter);
    }

    auto ec_block_attr = tx_info.add_attr();
    ec_block_attr->set_key(kElectNodeAttrElectBlock);
    ec_block_attr->set_value(ec_block.SerializeAsString());
    return kElectSuccess;
}

int ElectPoolManager::BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info) {
    common::BloomFilter leader_cons_all;
    common::BloomFilter leader_cons_weed_out;
    common::BloomFilter leader_pick_all;
    common::BloomFilter leader_pick_in;
    elect::protobuf::ElectBlock leader_ec_block;
    if (GetAllTxInfoBloomFiler(
            tx_info,
            &leader_cons_all,
            &leader_cons_weed_out,
            &leader_pick_all,
            &leader_pick_in,
            &leader_ec_block) != kElectSuccess) {
        ELECT_ERROR("GetAllTxInfoBloomFiler failed!");
        return kElectError;
    }

    common::BloomFilter local_cons_all;
    common::BloomFilter local_cons_weed_out;
    common::BloomFilter local_pick_all;
    common::BloomFilter local_pick_in;
    elect::protobuf::ElectBlock local_ec_block;
    if (GetAllTxInfoBloomFiler(
            local_tx_info,
            &local_cons_all,
            &local_cons_weed_out,
            &local_pick_all,
            &local_pick_in,
            &local_ec_block) != kElectSuccess) {
        ELECT_ERROR("GetAllTxInfoBloomFiler failed!");
        return kElectError;
    }

    // exists shard nodes must equal
    if (local_cons_all != leader_cons_all) {
        ELECT_ERROR("local_cons_all != leader_cons_all!");
        return kElectError;
    }

    if (local_cons_weed_out != leader_cons_weed_out) {
        ELECT_ERROR("cons_weed_out != leader_cons_weed_out!");
        return kElectError;
    }

    if (local_pick_all != leader_pick_all) {
        ELECT_ERROR("pick_all != leader_pick_all!");
        return kElectError;
    }

    if (local_pick_in != leader_pick_in) {
        ELECT_ERROR("pick_in != leader_pick_in");
        return kElectError;
    }

    if (leader_ec_block.in_size() != local_ec_block.in_size()) {
        ELECT_ERROR("leader_ec_block.in_size() error!");
        return kElectError;
    }

    for (int32_t leader_idx = 0; leader_idx < leader_ec_block.in_size(); ++leader_idx) {
        if (leader_ec_block.in(leader_idx).pubkey() != local_ec_block.in(leader_idx).pubkey()) {
            ELECT_ERROR("leader_ec_block public key not equal local public key error!");
            return kElectError;
        }

        if (leader_ec_block.in(leader_idx).pool_idx_mod_num() !=
                local_ec_block.in(leader_idx).pool_idx_mod_num()) {
            ELECT_ERROR("leader_ec_block pool_idx_mod_num not equal local error!");
            return kElectError;
        }
    }

    return kElectSuccess;
}

void ElectPoolManager::OnTimeBlock(uint64_t tm_block_tm) {
    std::unordered_map<uint32_t, ElectWaitingNodesPtr> waiting_pool_map;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        waiting_pool_map = waiting_pool_map_;
    }

    for (auto iter = waiting_pool_map.begin(); iter != waiting_pool_map.end(); ++iter) {
        iter->second->OnTimeBlock(tm_block_tm);
    }
}

void ElectPoolManager::AddWaitingPoolNode(uint32_t network_id, NodeDetailPtr& node_ptr) {
    if (network_id < network::kRootCongressWaitingNetworkId ||
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

void ElectPoolManager::UpdateNodesStoke() {
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        std::unordered_map<uint32_t, ElectWaitingNodesPtr> waiting_pool_map;
        {
            std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
            waiting_pool_map = waiting_pool_map_;
        }

        for (auto iter = waiting_pool_map.begin(); iter != waiting_pool_map.end(); ++iter) {
            iter->second->UpdateWaitingNodeStoke();
            usleep(100000);
        }

        std::unordered_map<uint32_t, ElectPoolPtr> elect_pool_map;
        {
            std::lock_guard<std::mutex> guard(elect_pool_map_mutex_);
            elect_pool_map = elect_pool_map_;
        }

        for (auto iter = elect_pool_map.begin(); iter != elect_pool_map.end(); ++iter) {
            iter->second->UpdateNodesStoke();
            usleep(100000);
        }
    }

    update_stoke_tick_.CutOff(30000000l, std::bind(&ElectPoolManager::UpdateNodesStoke, this));
}

void ElectPoolManager::UpdateWaitingNodes(
        const protobuf::WaitingNodesMessage& waiting_nodes,
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter) {
    auto waiting_shard_id = waiting_nodes.waiting_shard_id();
    if (waiting_shard_id < network::kRootCongressWaitingNetworkId ||
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

    waiting_pool_ptr->UpdateWaitingNodes(root_node_id, waiting_nodes.stoke_hash(), nodes_filter);
}

void ElectPoolManager::GetInvalidLeaders(
        uint32_t network_id,
        const block::protobuf::StatisticInfo& statistic_info,
        std::map<int32_t, uint32_t>* nodes) {
    for (int32_t i = 0; i < statistic_info.elect_statistic_size(); ++i) {
        if (elect::ElectManager::Instance()->latest_height(network_id) !=
                statistic_info.elect_statistic(i).elect_height()) {
            continue;
        }

        auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
            statistic_info.elect_statistic(i).elect_height(),
            network_id,
            nullptr,
            nullptr);
        for (int32_t lof_idx = 0;
                lof_idx < statistic_info.elect_statistic(i).lof_leaders_size(); ++lof_idx) {
            if (statistic_info.elect_statistic(i).lof_leaders(lof_idx) >= members->size()) {
                continue;
            }

            (*nodes)[statistic_info.elect_statistic(i).lof_leaders(lof_idx)] = 0;
        }
    }
}

using KItemType = std::pair<int32_t, uint32_t>;
struct CompareItem {
    bool operator() (const KItemType& l, const KItemType& r) {
        return l.second < r.second;
    }
};

void ElectPoolManager::GetMiniTopNInvalidNodes(
        uint32_t network_id,
        const block::protobuf::StatisticInfo& statistic_info,
        uint32_t count,
        std::map<int32_t, uint32_t>* nodes) {
    std::priority_queue<KItemType, std::vector<KItemType>, CompareItem> kqueue;
    for (int32_t i = 0; i < statistic_info.elect_statistic_size(); ++i) {
        if (elect::ElectManager::Instance()->latest_height(network_id) !=
                statistic_info.elect_statistic(i).elect_height()) {
            continue;
        }

        auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
            statistic_info.elect_statistic(i).elect_height(),
            network_id,
            nullptr,
            nullptr);
        uint32_t all_tx_count = 0;
        if (members->size() == (uint32_t)statistic_info.elect_statistic(i).succ_tx_count_size()) {
            for (uint32_t cound_idx = 0; cound_idx < members->size(); ++cound_idx) {
                kqueue.push(std::pair<int32_t, uint32_t>(
                    cound_idx,
                    statistic_info.elect_statistic(i).succ_tx_count(cound_idx)));
                all_tx_count += statistic_info.elect_statistic(i).succ_tx_count(cound_idx);
                if (kqueue.size() > count) {
                    kqueue.pop();
                }
            }

            auto avg_tx_count = all_tx_count / members->size();
            while (!kqueue.empty()) {
                auto item = kqueue.top();
                if (item.second < avg_tx_count) {
                    (*nodes)[item.first] = item.second;
                }

                kqueue.pop();
            }
        }
    }
}

int ElectPoolManager::GetAllBloomFilerAndNodes(
        const block::protobuf::StatisticInfo& statistic_info,
        uint32_t shard_netid,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        std::vector<NodeDetailPtr>& elected_nodes,
        std::set<std::string>& weed_out_ids) {
    uint64_t etime0 = common::TimeUtils::TimestampMs();
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
    std::vector<NodeDetailPtr> exists_shard_nodes;
    consensus_pool_ptr->GetAllValidNodes(*cons_all, exists_shard_nodes);
    uint32_t weed_out_count = exists_shard_nodes.size() * kFtsWeedoutDividRate / 100;
    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(shard_netid + network::kConsensusWaitingShardOffset);
        if (iter != waiting_pool_map_.end()) {
            waiting_pool_ptr = iter->second;
        }
    }

    std::set<int32_t> pick_in_vec;
    std::vector<NodeDetailPtr> pick_all_vec;
    if (waiting_pool_ptr != nullptr) {
        waiting_pool_ptr->GetAllValidNodes(*pick_all, pick_all_vec);
        if (!pick_all_vec.empty()) {
            for (auto iter = pick_all_vec.begin(); iter != pick_all_vec.end(); ++iter) {
                (*iter)->init_pool_index_mod_num = -1;
            }

            if (statistic_info.all_tx_count() / 2 * 3 >= kEachShardMaxTps) {
                // TODO: statistic to add new consensus shard
            }

            uint32_t pick_in_count = weed_out_count;
            if (elect::ElectManager::Instance()->GetMemberCount(shard_netid) <
                    (int32_t)common::kEachShardMaxNodeCount) {
                pick_in_count += weed_out_count / 2;
                if (pick_in_count <= 0) {
                    pick_in_count = 1;
                }

                if (pick_in_count + elect::ElectManager::Instance()->GetMemberCount(shard_netid) >
                        (int32_t)common::kEachShardMaxNodeCount) {
                    pick_in_count = common::kEachShardMaxNodeCount -
                        elect::ElectManager::Instance()->GetMemberCount(shard_netid);
                }

                if (pick_in_count <= weed_out_count) {
                    pick_in_count = weed_out_count + 1;
                }
            }

            FtsGetNodes(
                shard_netid,
                false,
                pick_in_count,
                pick_in,
                pick_all_vec,
                pick_in_vec);
        }
    }

    // Optimize a certain ratio of nodes with the smallest amount of sharing
    std::map<int32_t, uint32_t> direct_weed_out;
    GetMiniTopNInvalidNodes(
        shard_netid,
        statistic_info,
        exists_shard_nodes.size() * kInvalidShardNodesRate / 100,
        &direct_weed_out);
    GetInvalidLeaders(shard_netid, statistic_info, &direct_weed_out);
    std::set<int32_t> weed_out_set;
    for (auto iter = direct_weed_out.begin(); iter != direct_weed_out.end(); ++iter) {
        if ((uint32_t)iter->first >= exists_shard_nodes.size()) {
            return kElectError;
        }

        if (pick_in_vec.size() >= weed_out_count || iter->second == 0) {
            weed_out_set.insert(iter->first);
        }
    }

    if (weed_out_count >= weed_out_set.size()) {
        weed_out_count -= weed_out_set.size();
    } else {
        weed_out_count = 0;
    }

    if (pick_in_vec.size() < weed_out_count + weed_out_set.size()) {
        if (pick_in_vec.size() < weed_out_set.size()) {
            weed_out_count = 0;
        } else {
            weed_out_count = pick_in_vec.size() - weed_out_set.size();
        }
    }

    if (weed_out_count > 0) {
        FtsGetNodes(
            shard_netid,
            true,
            weed_out_count,
            cons_weed_out,
            exists_shard_nodes,
            weed_out_set);
    }
    std::set<std::string> elected_ids;
    int32_t idx = 0;
    for (auto iter = exists_shard_nodes.begin(); iter != exists_shard_nodes.end(); ++iter) {
        cons_all->Add(common::Hash::Hash64((*iter)->id));
        if (weed_out_set.find(idx++) != weed_out_set.end()) {
            weed_out_ids.insert((*iter)->id);
            continue;
        }

        if (elected_ids.find((*iter)->id) != elected_ids.end()) {
            continue;
        }

        elected_ids.insert((*iter)->id);
        elected_nodes.push_back(*iter);
    }

    for (auto iter = pick_in_vec.begin(); iter != pick_in_vec.end(); ++iter) {
        if (elected_ids.find(pick_all_vec[*iter]->id) != elected_ids.end()) {
            continue;
        }

        elected_ids.insert(pick_all_vec[*iter]->id);
        elected_nodes.push_back(pick_all_vec[*iter]);
    }

    struct RangGen {
        int operator() (int n) {
            return std::rand() / (1.0 + RAND_MAX) * n;
        }
    };

    std::srand(static_cast<uint32_t>(vss::VssManager::Instance()->EpochRandom() % RAND_MAX));
    std::random_shuffle(elected_nodes.begin(), elected_nodes.end(), RangGen());
    return kElectSuccess;
}

int ElectPoolManager::SelectLeader(
        uint32_t network_id,
        const common::Bitmap& bitmap,
        elect::protobuf::ElectBlock* ec_block) {
    auto members = elect::ElectManager::Instance()->GetWaitingNetworkMembers(network_id);
    if (members == nullptr) {
        BLS_ERROR("get waiting members failed![%u]", network_id);
        return kElectError;
    }

    int32_t expect_leader_count = (int32_t)pow(
        2.0,
        (double)((int32_t)log2(double(members->size() / 3))));
    if (expect_leader_count > (int32_t)common::kImmutablePoolSize) {
        expect_leader_count = (int32_t)common::kImmutablePoolSize;
    }

    assert(expect_leader_count > 0);
    common::BloomFilter tmp_filter(kBloomfilterSize, kBloomfilterHashCount);
    std::vector<NodeDetailPtr> elected_nodes;
    uint32_t mem_idx = 0;
    for (auto iter = members->begin(); iter != members->end(); ++iter, ++mem_idx) {
        if (!bitmap.Valid(mem_idx)) {
            continue;
        }

        auto elect_node = std::make_shared<ElectNodeDetail>();
        elect_node->index = mem_idx;
        elect_node->id = (*iter)->id;
        elect_node->public_ip = (*iter)->public_ip;
        elect_node->public_port = (*iter)->public_port;
        elect_node->dht_key = (*iter)->dht_key;
        std::string pubkey_str;
        (*iter)->pubkey.Serialize(pubkey_str);
        elect_node->public_key = pubkey_str;
        elected_nodes.push_back(elect_node);
    }

    std::set<int32_t> leader_nodes;
    FtsGetNodes(
        network_id,
        false,
        expect_leader_count,
        &tmp_filter,
        elected_nodes,
        leader_nodes);
    if (leader_nodes.empty()) {
        BFT_ERROR("fts get leader nodes failed! elected_nodes size: %u", elected_nodes.size());
        return kElectError;
    }

    int32_t mode_idx = 0;
    std::unordered_map<std::string, int32_t> leader_mode_idx_map;
//     ELECT_ERROR("SelectLeader expect_leader_count: %u, leader_nodes: size: %d, all size: %d, random: %lu",
//         expect_leader_count, leader_nodes.size(), members->size(), vss::VssManager::Instance()->EpochRandom());
    for (int32_t i = 0; i < ec_block->prev_members().bls_pubkey_size(); ++i) {
        ec_block->mutable_prev_members()->mutable_bls_pubkey(i)->set_pool_idx_mod_num(-1);
    }

    for (auto iter = leader_nodes.begin(); iter != leader_nodes.end(); ++iter) {
        if (ec_block->prev_members().bls_pubkey_size() <= elected_nodes[*iter]->index) {
            return kElectError;
        }

        auto* bls_key = ec_block->mutable_prev_members()->mutable_bls_pubkey(elected_nodes[*iter]->index);
        bls_key->set_pool_idx_mod_num(mode_idx++);
//         ELECT_ERROR("SelectLeader expect_leader_count: %u, leader_nodes: size: %d, all size: %d, index: %d",
//             expect_leader_count, leader_nodes.size(), members->size(), (*iter)->index);
    }

    if (mode_idx != expect_leader_count) {
        assert(false);
        return kElectError;
    }

    return kElectSuccess;
}

void ElectPoolManager::FtsGetNodes(
        uint32_t shard_netid,
        bool weed_out,
        uint32_t count,
        common::BloomFilter* nodes_filter,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::set<int32_t>& res_nodes) {
    auto sort_vec = src_nodes;
    std::mt19937_64 g2(vss::VssManager::Instance()->EpochRandom());
    SmoothFtsValue(
        shard_netid,
        (src_nodes.size() - (src_nodes.size() / 3)),
        g2,
        sort_vec);
    std::set<int32_t> tmp_res_nodes;
    uint32_t try_times = 0;
    while (tmp_res_nodes.size() < count) {
        common::FtsTree fts_tree;
        int32_t idx = 0;
        for (auto iter = src_nodes.begin(); iter != src_nodes.end(); ++iter, ++idx) {
            if (tmp_res_nodes.find(idx) != tmp_res_nodes.end()) {
                continue;
            }

            uint64_t fts_value = (*iter)->fts_value;
            if (weed_out) {
                fts_value = common::kTenonMaxAmount - fts_value;
            }

            fts_tree.AppendFtsNode(fts_value, idx);
        }

        fts_tree.CreateFtsTree();
        int32_t data = fts_tree.GetOneNode(g2);
        if (data == -1) {
            ++try_times;
            if (try_times > 5) {
                ELECT_ERROR("fts get bft nodes failed! tmp_res_nodes size: %d", tmp_res_nodes.size());
                return;
            }
            continue;
        }

        try_times = 0;
        tmp_res_nodes.insert(data);
//         NodeDetailPtr node_ptr = *((NodeDetailPtr*)data);
        res_nodes.insert(data);
        nodes_filter->Add(common::Hash::Hash64(src_nodes[data]->id));
    }
}

void ElectPoolManager::SmoothFtsValue(
        uint32_t shard_netid,
        int32_t count,
        std::mt19937_64& g2,
        std::vector<NodeDetailPtr>& sort_vec) {
    assert(sort_vec.size() >= (uint32_t)count);
    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceCompare);
    sort_vec[0]->choosed_balance = NodesStokeManager::Instance()->GetAddressStoke(sort_vec[0]->id);
    ELECT_DEBUG("TTTTTTTTT smooth get blance: %s, %lu",
        common::Encode::HexEncode(sort_vec[0]->id).c_str(),
        (uint64_t)sort_vec[0]->choosed_balance);
    for (uint32_t i = 1; i < sort_vec.size(); ++i) {
        sort_vec[i]->choosed_balance = NodesStokeManager::Instance()->GetAddressStoke(sort_vec[i]->id);
        ELECT_DEBUG("TTTTTTTTT smooth get blance: %s, %lu",
            common::Encode::HexEncode(sort_vec[i]->id).c_str(),
            (uint64_t)sort_vec[i]->choosed_balance);
        sort_vec[i]->balance_diff = sort_vec[i]->choosed_balance - sort_vec[i - 1]->choosed_balance;
    }

    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceDiffCompare);
    uint64_t diff_2b3 = sort_vec[sort_vec.size() * 2 / 3]->balance_diff;
    std::sort(sort_vec.begin(), sort_vec.end(), ElectNodeBalanceCompare);
    std::vector<int32_t> blance_weight;
    blance_weight.resize(sort_vec.size());
    blance_weight[0] = 100;
    int32_t min_balance = (std::numeric_limits<int32_t>::max)();
    int32_t max_balance = 0;
    for (uint32_t i = 1; i < sort_vec.size(); ++i) {
        uint64_t fts_val_diff = sort_vec[i]->choosed_balance - sort_vec[i - 1]->choosed_balance;
        if (fts_val_diff == 0) {
            blance_weight[i] = blance_weight[i - 1];
        } else {
            if (fts_val_diff < diff_2b3) {
                auto rand_val = fts_val_diff + g2() % (diff_2b3 - fts_val_diff);
                blance_weight[i] = blance_weight[i - 1] + (20 * rand_val) / diff_2b3;
            } else {
                auto rand_val = diff_2b3 + g2() % (fts_val_diff + 1 - diff_2b3);
                blance_weight[i] = blance_weight[i - 1] + (20 * rand_val) / fts_val_diff;
            }
        }

        if (min_balance > blance_weight[i]) {
            min_balance = blance_weight[i];
        }

        if (max_balance < blance_weight[i]) {
            max_balance = blance_weight[i];
        }
    }

    // at least [100, 1000] for fts
    int32_t blance_diff = max_balance - min_balance;
    if (max_balance - min_balance < 1000) {
        auto old_balance_diff = max_balance - min_balance;
        max_balance = min_balance + 1000;
        blance_diff = max_balance - min_balance;
        if (old_balance_diff > 0) {
            int32_t balance_index = blance_diff / old_balance_diff;
            for (uint32_t i = 0; i < sort_vec.size(); ++i) {
                blance_weight[i] = min_balance + balance_index * (blance_weight[i] - min_balance);
            }
        }
    }

    std::vector<int32_t> credit_weight;
    credit_weight.resize(sort_vec.size());
    int32_t min_credit = (std::numeric_limits<int32_t>::max)();
    int32_t max_credit = (std::numeric_limits<int32_t>::min)();
    for (uint32_t i = 0; i < sort_vec.size(); ++i) {
        int32_t credit = common::kInitNodeCredit;
        node_credit_.GetNodeHistoryCredit(sort_vec[i]->id, &credit);
        credit_weight[i] = credit;
        if (min_credit > credit) {
            min_credit = credit;
        }

        if (max_credit < credit) {
            max_credit = credit;
        }
    }

    int32_t credit_diff = max_credit - min_credit;
    if (credit_diff > 0) {
        int32_t credit_index = blance_diff / credit_diff;
        for (uint32_t i = 0; i < sort_vec.size(); ++i) {
            credit_weight[i] = min_balance + credit_index * (credit_weight[i] - min_credit);
        }
    }

    std::vector<int32_t> ip_weight;
    ip_weight.resize(sort_vec.size());
    auto choosed_ip_weight = elect::ElectManager::Instance()->GetIpWeight(
        elect::ElectManager::Instance()->latest_height(shard_netid),
        shard_netid);
    int32_t min_ip_weight = (std::numeric_limits<int32_t>::max)();
    int32_t max_ip_weight = (std::numeric_limits<int32_t>::min)();
    for (uint32_t i = 0; i < sort_vec.size(); ++i) {
        int32_t prefix_len = 0;
        auto count = choosed_ip_weight.GetIpCount(sort_vec[i]->public_ip, &prefix_len);
        ip_weight[i] = prefix_len;
        if (ip_weight[i] > max_ip_weight) {
            max_ip_weight = ip_weight[i];
        }

        if (ip_weight[i] < min_ip_weight) {
            min_ip_weight = ip_weight[i];
        }
    }

    for (uint32_t i = 0; i < sort_vec.size(); ++i) {
        ip_weight[i] = max_ip_weight - ip_weight[i];
    }

    int32_t weight_diff = max_ip_weight - min_ip_weight;
    if (weight_diff > 0) {
        int32_t weight_index = blance_diff / weight_diff;
        for (uint32_t i = 0; i < sort_vec.size(); ++i) {
            ip_weight[i] = min_balance + weight_index * (ip_weight[i] - min_ip_weight);
        }
    }

    for (uint32_t i = 0; i < sort_vec.size(); ++i) {
        sort_vec[i]->fts_value = (3 * ip_weight[i] + 4 * credit_weight[i] + 3 * blance_weight[i]) / 10;
        ELECT_DEBUG("fts smooth %s: %d, %d, %d, %d",
            common::Encode::HexEncode(sort_vec[i]->id).c_str(),
            sort_vec[i]->fts_value, ip_weight[i], credit_weight[i], blance_weight[i]);
        std::cout << common::Encode::HexEncode(sort_vec[i]->id) << " : "
            << sort_vec[i]->fts_value << ", "
            << ip_weight[i] << ", "
            << credit_weight[i] << ", "
            << blance_weight[i] << std::endl;
    }
}

int ElectPoolManager::GetAllTxInfoBloomFiler(
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

    ElectWaitingNodesPtr waiting_pool_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(waiting_pool_map_mutex_);
        auto iter = waiting_pool_map_.find(network_id + network::kConsensusWaitingShardOffset);
        if (iter != waiting_pool_map_.end()) {
            waiting_pool_ptr = iter->second;
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
        elect_node->init_pool_index_mod_num = -1;
        node_vec.push_back(elect_node);
    }

    pool_ptr->ReplaceWithElectNodes(node_vec);
    if (waiting_pool_ptr != nullptr) {
        waiting_pool_ptr->RemoveNodes(node_vec);
    }
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
