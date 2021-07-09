#include "stdafx.h"
#include "election/elect_manager.h"

#include <functional>

#include "bft/bft_manager.h"
#include "common/utils.h"
#include "common/time_utils.h"
#include "dht/dht_utils.h"
#include "db/db_utils.h"
#include "election/proto/elect_proto.h"
#include "network/route.h"
#include "network/shard_network.h"
#include "security/secp256k1.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace elect {

ElectManager* ElectManager::Instance() {
    static ElectManager ins;
    return &ins;
}

ElectManager::ElectManager() {
    network::Route::Instance()->RegisterMessage(
        common::kElectMessage,
        std::bind(&ElectManager::HandleMessage, this, std::placeholders::_1));
    waiting_hb_tick_.CutOff(
        kWaitingHeartbeatPeriod,
        std::bind(&ElectManager::WaitingNodeSendHeartbeat, this));
}

ElectManager::~ElectManager() {}

int ElectManager::Join(uint32_t network_id) {
    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter != elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkJoined;
        }
    }

    elect_node_ptr_ = std::make_shared<ElectNode>(
        network_id,
        std::bind(
            &ElectManager::GetMemberWithId,
            this,
            std::placeholders::_1,
            std::placeholders::_2));
    if (elect_node_ptr_->Init() != network::kNetworkSuccess) {
        ELECT_ERROR("node join network [%u] failed!", network_id);
        return kElectError;
    }

    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter != elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkJoined;
        }

        elect_network_map_[network_id] = elect_node_ptr_;
    }

    return kElectSuccess;
}

int ElectManager::Quit(uint32_t network_id) {
    ElectNodePtr elect_node = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter == elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkNotJoined;
        }

        elect_node = iter->second;
        elect_network_map_.erase(iter);
    }

    elect_node->Destroy();
    return kElectSuccess;
}

void ElectManager::OnTimeBlock(uint64_t tm_block_tm) {
    pool_manager_.OnTimeBlock(tm_block_tm);
}

void ElectManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kElectMessage);
    // TODO: verify message signature
    protobuf::ElectMessage ec_msg;
    if (!ec_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (!security::IsValidPublicKey(ec_msg.pubkey())) {
        ELECT_ERROR("invalid public key: %s!", common::Encode::HexEncode(ec_msg.pubkey()));
        return;
    }

    if (!security::IsValidSignature(ec_msg.sign_ch(), ec_msg.sign_res())) {
        ELECT_ERROR("invalid sign: %s, %s!",
            common::Encode::HexEncode(ec_msg.sign_ch()),
            common::Encode::HexEncode(ec_msg.sign_res()));
        return;
    }

    if (ec_msg.has_waiting_nodes()) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(ec_msg.pubkey());
        auto mem_ptr = GetMember(network::kRootCongressNetworkId, id);
        if (mem_ptr) {
            std::vector<uint64_t> filter_vec;
            for (int32_t i = 0; i < ec_msg.waiting_nodes().nodes_filter_size(); ++i) {
                filter_vec.push_back(ec_msg.waiting_nodes().nodes_filter(i));
            }

            common::BloomFilter fiter(filter_vec, kBloomfilterWaitingHashCount);
            std::string hash_str = fiter.Serialize() +
                std::to_string(ec_msg.waiting_nodes().waiting_shard_id());
            auto message_hash = common::Hash::keccak256(hash_str);
            auto pubkey = security::PublicKey(ec_msg.pubkey());
            auto sign = security::Signature(ec_msg.sign_ch(), ec_msg.sign_res());
            if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
                return;
            }

            pool_manager_.UpdateWaitingNodes(
                ec_msg.waiting_nodes().waiting_shard_id(),
                id,
                fiter);
        }
    }

    if (ec_msg.has_waiting_heartbeat()) {
        if (ec_msg.waiting_heartbeat().network_id() >= network::kRootCongressWaitingNetworkId &&
                ec_msg.waiting_heartbeat().network_id() < network::kConsensusWaitingShardEndNetworkId) {
            auto now_tm_sec = common::TimeUtils::TimestampSeconds();
            if ((now_tm_sec >= ec_msg.waiting_heartbeat().timestamp_sec() &&
                now_tm_sec - ec_msg.waiting_heartbeat().timestamp_sec() < 10) ||
                (now_tm_sec <= ec_msg.waiting_heartbeat().timestamp_sec() &&
                    ec_msg.waiting_heartbeat().timestamp_sec() - now_tm_sec < 10)) {
                auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(
                    ec_msg.pubkey());
                if (IsIdExistsInAnyShard(
                        ec_msg.waiting_heartbeat().network_id() - network::kConsensusWaitingShardOffset,
                        id)) {
                    return;
                }

                // TODO: check public ip is added
                auto message_hash = GetElectHeartbeatHash(
                    ec_msg.waiting_heartbeat().public_ip(),
                    ec_msg.waiting_heartbeat().public_port(),
                    ec_msg.waiting_heartbeat().network_id(),
                    ec_msg.waiting_heartbeat().timestamp_sec());
                auto pubkey = security::PublicKey(ec_msg.pubkey());
                auto sign = security::Signature(ec_msg.sign_ch(), ec_msg.sign_res());
                if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
                    ELECT_ERROR("verify signature failed!");
                    return;
                }

                auto elect_node_ptr = std::make_shared<ElectNodeDetail>();
                elect_node_ptr->public_ip = ec_msg.waiting_heartbeat().public_ip();
                elect_node_ptr->public_port = ec_msg.waiting_heartbeat().public_port();
                elect_node_ptr->id = id;
                elect_node_ptr->public_key = ec_msg.pubkey();
                elect_node_ptr->join_tm = std::chrono::steady_clock::now();
                pool_manager_.AddWaitingPoolNode(ec_msg.waiting_heartbeat().network_id(), elect_node_ptr);
            }
        }
    }
}

void ElectManager::ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool load_from_db) {
    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    if (elect_members_.find(height) != elect_members_.end()) {
        return;
    }

    std::map<uint32_t, NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map;
    auto in = elect_block.in();
    auto shard_members_ptr = std::make_shared<Members>();
    auto shard_members_index_ptr = std::make_shared<
        std::unordered_map<std::string, uint32_t>>();
    uint32_t member_index = 0;
    ClearExistsNetwork(elect_block.shard_network_id());
    for (int32_t i = 0; i < in.size(); ++i) {
        security::CommitSecret secret;
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        shard_members_ptr->push_back(std::make_shared<BftMember>(
            elect_block.shard_network_id(),
            id,
            in[i].pubkey(),
            member_index,
            in[i].public_ip(),
            in[i].public_port(),
            in[i].dht_key(),
            in[i].pool_idx_mod_num()));
        AddNewNodeWithIdAndIp(elect_block.shard_network_id(), id, in[i].public_ip());
        (*shard_members_index_ptr)[id] = member_index;
        if (load_from_db && in[i].has_public_ip()) {
            dht::NodePtr node = std::make_shared<dht::Node>(
                id,
                in[i].dht_key(),
                in[i].nat_type(),
                false,
                in[i].public_ip(),
                in[i].public_port(),
                in[i].local_ip(),
                in[i].local_port(),
                in[i].pubkey(),
                "bft");
            node->join_way = dht::kJoinFromElectBlock;
            int join_res = elect_node_ptr_->GetDht()->Join(node);
            network::UniversalManager::Instance()->AddNodeToUniversal(node);
        }

        if (id == common::GlobalInfo::Instance()->id()) {
            if (common::GlobalInfo::Instance()->network_id() != elect_block.shard_network_id()) {
                Quit(common::GlobalInfo::Instance()->network_id());
                if (Join(elect_block.shard_network_id()) != kElectSuccess) {
                    BFT_ERROR("join elected network failed![%u]", elect_block.shard_network_id());
                }

                common::GlobalInfo::Instance()->set_network_id(elect_block.shard_network_id());
            }
        }

        ++member_index;
    }

    {
        local_node_is_super_leader_ = false;
        Members tmp_leaders;
        std::vector<uint32_t> node_index_vec;
        uint32_t index = 0;
        for (auto iter = shard_members_ptr->begin(); iter != shard_members_ptr->end(); ++iter) {
            if ((*iter)->pool_index_mod_num() >= 0) {
                tmp_leaders.push_back(*iter);
                node_index_vec.push_back(index++);
            }

            ELECT_DEBUG("DDDDDDDDDDDDDDDDDD ProcessNewElectBlock network: %d,"
                "member leader: %s,, (*iter)->pool_index_mod_num: %d",
                elect_block.shard_network_id(),
                common::Encode::HexEncode((*iter)->id).c_str(),
                (*iter)->pool_index_mod_num());
            std::cout << "DDDDDDDDDDDDDDDDDD ProcessNewElectBlock network: "
                << elect_block.shard_network_id()
                << ", member leader: " << common::Encode::HexEncode((*iter)->id)
                << ", (*iter)->pool_index_mod_num: " << (*iter)->pool_index_mod_num()
                << ", leader count: " << elect_block.leader_count()
                << std::endl;
        }

        std::mt19937_64 g2(vss::VssManager::Instance()->EpochRandom());
        auto RandFunc = [&g2](int i) -> int {
            return g2() % i;
        };
        std::random_shuffle(node_index_vec.begin(), node_index_vec.end(), RandFunc);
        std::lock_guard<std::mutex> guard(network_leaders_mutex_);
        std::unordered_set<std::string> leaders;
        for (auto iter = node_index_vec.begin();
                iter != node_index_vec.end() &&
                leaders.size() < common::kEatchShardMaxSupperLeaderCount; ++iter) {
            leaders.insert(tmp_leaders[*iter]->id);
            if (tmp_leaders[*iter]->id == common::GlobalInfo::Instance()->id()) {
                local_node_is_super_leader_ = true;
            }
        }

        network_leaders_[elect_block.shard_network_id()] = leaders;
    }

    pool_manager_.NetworkMemberChange(elect_block.shard_network_id(), shard_members_ptr);
    auto member_ptr = std::make_shared<MemberManager>();
    member_ptr->SetNetworkMember(
        elect_block.shard_network_id(),
        shard_members_ptr,
        shard_members_index_ptr,
        elect_block.leader_count());
    {
        std::lock_guard<std::mutex> guard(valid_shard_networks_mutex_);
        valid_shard_networks_.insert(elect_block.shard_network_id());
    }

    elect_members_[height] = member_ptr;
    auto net_heights_iter = elect_net_heights_map_.find(elect_block.shard_network_id());
    if (net_heights_iter == elect_net_heights_map_.end()) {
        elect_net_heights_map_[elect_block.shard_network_id()] = height;
    } else {
        if (height > net_heights_iter->second) {
            net_heights_iter->second = height;
        }
    }
}

int ElectManager::BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.BackupCheckElectionBlockTx(local_tx_info, tx_info);
}

int ElectManager::CreateElectTransaction(
        uint32_t shard_netid,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info) {
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        return kElectError;
    }

    return pool_manager_.CreateElectTransaction(shard_netid, src_tx_info, tx_info);
}

int ElectManager::GetElectionTxInfo(bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.GetElectionTxInfo(tx_info);
}

uint64_t ElectManager::latest_height(uint32_t network_id) {
    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    auto net_heights_iter = elect_net_heights_map_.find(network_id);
    if (net_heights_iter == elect_net_heights_map_.end()) {
        return common::kInvalidUint64;
    }

    return net_heights_iter->second;
}

int32_t ElectManager::IsLeader(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            ELECT_ERROR("elect_height == common::kInvalidUint64");
            return -1;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {    
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            ELECT_ERROR("iter == elect_members_.end()[%lu]", elect_height);
            return -1;
        }

        mem_ptr = iter->second;
    }

    ELECT_DEBUG("IsLeader elect_height: %lu, network_id: %u, node_id: %s",
        elect_height, network_id, common::Encode::HexEncode(node_id).c_str());
    return mem_ptr->IsLeader(network_id, node_id);
}

uint32_t ElectManager::GetMemberIndex(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return kInvalidMemberIndex;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return kInvalidMemberIndex;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetMemberIndex(network_id, node_id);
}

elect::MembersPtr ElectManager::GetNetworkMembers(uint64_t elect_height, uint32_t network_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return nullptr;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return nullptr;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetNetworkMembers(network_id);
}

elect::BftMemberPtr ElectManager::GetMember(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return nullptr;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return nullptr;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetMember(network_id, node_id);
}

elect::BftMemberPtr ElectManager::GetMember(
        uint64_t elect_height,
        uint32_t network_id,
        uint32_t index) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return nullptr;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return nullptr;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetMember(network_id, index);
}

uint32_t ElectManager::GetMemberCount(uint64_t elect_height, uint32_t network_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return 0;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return 0;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetMemberCount(network_id);
}

int32_t ElectManager::GetNetworkLeaderCount(uint64_t elect_height, uint32_t network_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return 0;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return 0;
        }

        mem_ptr = iter->second;
    }

    return mem_ptr->GetNetworkLeaderCount(network_id);
}

void ElectManager::SetNetworkMember(
        uint64_t elect_height,
        uint32_t network_id,
        elect::MembersPtr& members_ptr,
        elect::NodeIndexMapPtr& node_index_map,
        int32_t leader_count) {
    if (elect_height == common::kInvalidUint64) {
        return;
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter != elect_members_.end()) {
            return;
        }

        mem_ptr = std::make_shared<elect::MemberManager>();
        elect_members_[elect_height] = mem_ptr;
        auto net_heights_iter = elect_net_heights_map_.find(network_id);
        if (net_heights_iter == elect_net_heights_map_.end()) {
            elect_net_heights_map_[network_id] = elect_height;
        } else {
            if (elect_height > net_heights_iter->second) {
                net_heights_iter->second = elect_height;
            }
        }
    }

    {
        Members tmp_leaders;
        uint32_t leader_count = GetNetworkLeaderCount(
            common::GlobalInfo::Instance()->network_id());
        std::mt19937_64 g2(vss::VssManager::Instance()->EpochRandom());
        std::vector<uint32_t> node_index_vec;
        uint32_t index = 0;
        for (auto iter = members_ptr->begin(); iter != members_ptr->end(); ++iter) {
            if ((*iter)->pool_index_mod_num() >= 0) {
                tmp_leaders.push_back(*iter);
                node_index_vec.push_back(index++);
            }
        }

        auto RandFunc = [&g2](int i) -> int {
            return g2() % i;
        };
        std::random_shuffle(node_index_vec.begin(), node_index_vec.end(), RandFunc);
        std::lock_guard<std::mutex> guard(network_leaders_mutex_);
        std::unordered_set<std::string> leaders;
        for (auto iter = node_index_vec.begin();
                iter != node_index_vec.end() &&
                leaders.size() < common::kEatchShardMaxSupperLeaderCount; ++iter) {
            leaders.insert(tmp_leaders[*iter]->id);
        }

        network_leaders_[network_id] = leaders;
    }

    return mem_ptr->SetNetworkMember(network_id, members_ptr, node_index_map, leader_count);
}

int32_t ElectManager::IsLeader(uint32_t network_id, const std::string& node_id) {
    return IsLeader(common::kInvalidUint64, network_id, node_id);
}

uint32_t ElectManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    return GetMemberIndex(common::kInvalidUint64, network_id, node_id);
}

elect::MembersPtr ElectManager::GetNetworkMembers(uint32_t network_id) {
    return GetNetworkMembers(common::kInvalidUint64, network_id);
}

elect::BftMemberPtr ElectManager::GetMemberWithId(
        uint32_t network_id,
        const std::string& node_id) {
    return GetMember(common::kInvalidUint64, network_id, node_id);
}

elect::BftMemberPtr ElectManager::GetMember(uint32_t network_id, const std::string& node_id) {
    return GetMember(common::kInvalidUint64, network_id, node_id);
}

elect::BftMemberPtr ElectManager::GetMember(uint32_t network_id, uint32_t index) {
    return GetMember(common::kInvalidUint64, network_id, index);
}

uint32_t ElectManager::GetMemberCount(uint32_t network_id) {
    return GetMemberCount(common::kInvalidUint64, network_id);
}

int32_t ElectManager::GetNetworkLeaderCount(uint32_t network_id) {
    return GetNetworkLeaderCount(common::kInvalidUint64, network_id);
}
bool ElectManager::IsValidShardLeaders(uint32_t network_id, const std::string& id) {
    // Each shard has a certain number of leaders
    // for the generation of public transaction blocks
    // if transaction create by this node, no balance change
    // and backup also check leader valid.
    std::lock_guard<std::mutex> guard(network_leaders_mutex_);
    auto iter = network_leaders_.find(network_id);
    if (iter == network_leaders_.end()) {
        return false;
    }

    return iter->second.find(id) != iter->second.end();
}

void ElectManager::WaitingNodeSendHeartbeat() {
    if (common::GlobalInfo::Instance()->network_id() >= network::kRootCongressWaitingNetworkId &&
            common::GlobalInfo::Instance()->network_id() <
            network::kConsensusWaitingShardEndNetworkId) {
        auto dht = network::DhtManager::Instance()->GetDht(
            common::GlobalInfo::Instance()->network_id());
        if (dht) {
            transport::protobuf::Header msg;
            elect::ElectProto::CreateWaitingHeartbeat(
                dht->local_node(),
                common::GlobalInfo::Instance()->network_id(),
                msg);
            if (msg.has_data()) {
                network::Route::Instance()->Send(msg);
            }
        }
    }

    waiting_hb_tick_.CutOff(
        kWaitingHeartbeatPeriod,
        std::bind(&ElectManager::WaitingNodeSendHeartbeat, this));
}

bool ElectManager::IsIdExistsInAnyShard(uint32_t network_id, const std::string& id) {
    std::lock_guard<std::mutex> guard(added_net_id_set_mutex_);
    auto iter = added_net_id_set_.find(network_id);
    if (iter != added_net_id_set_.end()) {
        return iter->second.find(id) != iter->second.end();
    }

    return false;
}

bool ElectManager::IsIpExistsInAnyShard(uint32_t network_id, const std::string& ip) {
    std::lock_guard<std::mutex> guard(added_net_ip_set_mutex_);
    auto iter = added_net_ip_set_.find(network_id);
    if (iter != added_net_id_set_.end()) {
        return iter->second.find(ip) != iter->second.end();
    }

    return false;
}

void ElectManager::ClearExistsNetwork(uint32_t network_id) {
    {
        std::lock_guard<std::mutex> guard(added_net_id_set_mutex_);
        added_net_id_set_[network_id] = std::unordered_set<std::string>();
    }

    {
        std::lock_guard<std::mutex> guard(added_net_ip_set_mutex_);
        added_net_ip_set_[network_id] = std::unordered_set<std::string>();
    }
}

void ElectManager::AddNewNodeWithIdAndIp(
        uint32_t network_id,
        const std::string& id,
        const std::string& ip) {
    {
        std::lock_guard<std::mutex> guard(added_net_id_set_mutex_);
        added_net_id_set_[network_id].insert(id);
    }

    {
        std::lock_guard<std::mutex> guard(added_net_ip_set_mutex_);
        added_net_ip_set_[network_id].insert(ip);
    }
}

}  // namespace elect

}  // namespace tenon
