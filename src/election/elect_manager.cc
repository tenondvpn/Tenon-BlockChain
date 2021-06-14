#include "stdafx.h"
#include "election/elect_manager.h"

#include <functional>

#include "common/utils.h"
#include "common/time_utils.h"
#include "db/db_utils.h"
#include "dht/dht_utils.h"
#include "network/route.h"
#include "bft/bft_manager.h"
#include "security/secp256k1.h"
#include "election/proto/elect_proto.h"
#include "network/shard_network.h"

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

int ElectManager::BackupCheckElectConsensusShard(const bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.BackupCheckElectionBlockTx(tx_info);
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
        auto now_tm_sec = common::TimeUtils::TimestampSeconds();
        if ((now_tm_sec >= ec_msg.waiting_heartbeat().timestamp_sec() &&
                now_tm_sec - ec_msg.waiting_heartbeat().timestamp_sec() < 10) ||
                (now_tm_sec <= ec_msg.waiting_heartbeat().timestamp_sec() &&
                ec_msg.waiting_heartbeat().timestamp_sec() - now_tm_sec < 10)) {
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
            elect_node_ptr->id = security::Secp256k1::Instance()->ToAddressWithPublicKey(
                ec_msg.pubkey());
            elect_node_ptr->public_key = ec_msg.pubkey();
            pool_manager_.AddWaitingPoolNode(ec_msg.waiting_heartbeat().network_id(), elect_node_ptr);
        }
    }
}

void ElectManager::ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool load_from_db) {
    std::map<uint32_t, MembersPtr> in_members;
    std::map<uint32_t, NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map;
    auto in = elect_block.in();
    for (int32_t i = 0; i < in.size(); ++i) {
        auto net_id = in[i].net_id();
        auto iter = in_members.find(net_id);
        if (iter == in_members.end()) {
            in_members[net_id] = std::make_shared<Members>();
            in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
            begin_index_map[net_id] = 0;
        }

        security::CommitSecret secret;
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        in_members[net_id]->push_back(std::make_shared<BftMember>(
            net_id,
            id,
            in[i].pubkey(),
            begin_index_map[net_id],
            in[i].public_ip(),
            in[i].public_port(),
            in[i].dht_key(),
            in[i].pool_idx_mod_num()));
        in_index_members[net_id]->insert(std::make_pair(id, begin_index_map[net_id]));
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
            elect_node_ptr_->GetDht()->Join(node);
            network::UniversalManager::Instance()->AddNodeToUniversal(node);
        }

        if (id == common::GlobalInfo::Instance()->id()) {
            if (common::GlobalInfo::Instance()->network_id() != net_id) {
                if (Join(net_id) != kElectSuccess) {
                    BFT_ERROR("join elected network failed![%u]", net_id);
                }

                common::GlobalInfo::Instance()->set_network_id(net_id);
            }
        }

        ++begin_index_map[net_id];
    }

    for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
        auto index_map_iter = in_index_members.find(iter->first);
        assert(index_map_iter != in_index_members.end());
        pool_manager_.NetworkMemberChange(iter->first, iter->second);
        auto member_ptr = std::make_shared<MemberManager>();
        member_ptr->SetNetworkMember(
            iter->first,
            iter->second,
            index_map_iter->second,
            elect_block.leader_count());
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        if (elect_members_.find(height) != elect_members_.end()) {
            return;
        }

        elect_members_[height] = member_ptr;
        auto net_heights_iter = elect_net_heights_map_.find(iter->first);
        if (net_heights_iter == elect_net_heights_map_.end()) {
            elect_net_heights_map_[iter->first] =
                std::make_shared<common::LimitHeap<uint64_t, 256, true>>(true);
            elect_net_heights_map_[iter->first]->push(height);
        } else {
            net_heights_iter->second->push(height);
        }

    }
}

void ElectManager::CreateAllElectTx() {

}

int ElectManager::CreateElectTransaction(
        uint32_t shard_netid,
        bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.CreateElectTransaction(shard_netid, src_tx_info, tx_info);
}

void ElectManager::CreateNewElectTx(uint32_t shard_network_id, transport::protobuf::Header* msg) {
    msg->set_src_dht_key("");
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg->set_des_dht_key(dht_key.StrKey());
    msg->set_priority(transport::kTransportPriorityHighest);
    msg->set_id(common::GlobalInfo::Instance()->MessageId());
    msg->set_type(common::kBftMessage);
    msg->set_client(false);
    msg->set_hop_count(0);
    auto broad_param = msg->mutable_broadcast();
    ElectProto::SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    pool_manager_.LeaderCreateElectionBlockTx(shard_network_id, bft_msg);
    msg->set_data(bft_msg.SerializeAsString());
}

uint64_t ElectManager::latest_height(uint32_t network_id) {
    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    auto net_heights_iter = elect_net_heights_map_.find(network_id);
    if (net_heights_iter == elect_net_heights_map_.end()) {
        return common::kInvalidUint64;
    }

    return net_heights_iter->second->top();
}

int32_t ElectManager::IsLeader(
        uint64_t elect_height,
        uint32_t network_id,
        const std::string& node_id) {
    if (elect_height == common::kInvalidUint64) {
        elect_height = latest_height(network_id);
        if (elect_height == common::kInvalidUint64) {
            return -1;
        }
    }

    std::shared_ptr<MemberManager> mem_ptr = nullptr;
    {    
        std::lock_guard<std::mutex> guard(elect_members_mutex_);
        auto iter = elect_members_.find(elect_height);
        if (iter == elect_members_.end()) {
            return -1;
        }

        mem_ptr = iter->second;
    }

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
            elect_net_heights_map_[network_id] = std::make_shared<common::LimitHeap<uint64_t, 256, true>>(true);
            elect_net_heights_map_[network_id]->push(elect_height);
        } else {
            net_heights_iter->second->push(elect_height);
        }
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

elect::BftMemberPtr ElectManager::GetMemberWithId(uint32_t network_id, const std::string& node_id) {
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

}  // namespace elect

}  // namespace tenon
