#include "stdafx.h"
#include "election/elect_manager.h"

#include <functional>

#include "bls/BLSPublicKey.h"
#include "bls/bls_manager.h"
#include "bft/bft_manager.h"
#include "block/block_manager.h"
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
    memset(latest_leader_count_, 0, sizeof(latest_leader_count_));
    memset(latest_member_count_, 0, sizeof(latest_member_count_));
    for (uint32_t i = 0; i < network::kConsensusShardEndNetworkId; ++i) {
        elect_net_heights_map_[i] = common::kInvalidUint64;
    }

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

void ElectManager::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
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
        auto mem_ptr = GetMemberWithId(network::kRootCongressNetworkId, id);
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

void ElectManager::OnNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block) {
    bool elected = false;
    ProcessPrevElectMembers(elect_block, &elected);
    ProcessNewElectBlock(height, elect_block, &elected);
    auto local_netid = common::GlobalInfo::Instance()->network_id();
    if (!elected) {
        if (local_netid == elect_block.shard_network_id()) {
            Quit(local_netid);
            if (Join(local_netid + network::kConsensusWaitingShardOffset) != kElectSuccess) {
                BFT_ERROR("join elected network failed![%u]",
                    local_netid + network::kConsensusWaitingShardOffset);
            } else {
                BFT_INFO("join new election shard network: %u",
                    local_netid + network::kConsensusWaitingShardOffset);
                common::GlobalInfo::Instance()->set_network_id(
                    local_netid + network::kConsensusWaitingShardOffset);
            }
        }
    } else {
        if (local_netid != elect_block.shard_network_id()) {
            Quit(local_netid);
            if (Join(elect_block.shard_network_id()) != kElectSuccess) {
                BFT_ERROR("join elected network failed![%u]", elect_block.shard_network_id());
            } else {
                BFT_INFO("join new election shard network: %u", elect_block.shard_network_id());
                common::GlobalInfo::Instance()->set_network_id(elect_block.shard_network_id());
            }
        }
    }
}

void ElectManager::ProcessPrevElectMembers(protobuf::ElectBlock& elect_block, bool* elected) {
    if (!elect_block.has_prev_members() &&
            elect_block.prev_members().prev_elect_height() <= 0) {
        return;
    }

    bft::protobuf::Block block_item;
    if (block::BlockManager::Instance()->GetBlockWithHeight(
            network::kRootCongressNetworkId,
            common::kRootChainPoolIndex,
            elect_block.prev_members().prev_elect_height(),
            block_item) != block::kBlockSuccess) {
        return;
    }

    if (block_item.tx_list_size() != 1) {
        return;
    }

    elect::protobuf::ElectBlock prev_elect_block;
    for (int32_t i = 0; i < block_item.tx_list(0).attr_size(); ++i) {
        if (block_item.tx_list(0).attr(i).key() == elect::kElectNodeAttrElectBlock) {
            prev_elect_block.ParseFromString(block_item.tx_list(0).attr(i).value());
        }
    }

    if (!prev_elect_block.IsInitialized()) {
        return;
    }

    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    if (added_height_.find(elect_block.prev_members().prev_elect_height()) != added_height_.end()) {
        return;
    }

    added_height_.insert(elect_block.prev_members().prev_elect_height());
    if (common::GlobalInfo::Instance()->network_id() == prev_elect_block.shard_network_id()) {
        local_node_pool_mod_num_ = -1;
        local_node_is_super_leader_ = false;
    }

    latest_member_count_[prev_elect_block.shard_network_id()] = prev_elect_block.in_size();
    latest_leader_count_[prev_elect_block.shard_network_id()] = prev_elect_block.leader_count();
    std::map<uint32_t, NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map;
    auto& in = prev_elect_block.in();
    auto shard_members_ptr = std::make_shared<Members>();
    auto shard_members_index_ptr = std::make_shared<
        std::unordered_map<std::string, uint32_t>>();
    uint32_t member_index = 0;
    ClearExistsNetwork(prev_elect_block.shard_network_id());
    for (int32_t i = 0; i < in.size(); ++i) {
        security::CommitSecret secret;
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        shard_members_ptr->push_back(std::make_shared<BftMember>(
            prev_elect_block.shard_network_id(),
            id,
            in[i].pubkey(),
            member_index,
            in[i].dht_key(),
            in[i].pool_idx_mod_num()));
        AddNewNodeWithIdAndIp(prev_elect_block.shard_network_id(), id, in[i].public_ip());
        (*shard_members_index_ptr)[id] = member_index;
        if (id == common::GlobalInfo::Instance()->id()) {
            *elected = true;
            local_node_member_index_ = i;
        }

        ++member_index;
    }

    {
        Members tmp_leaders;
        std::vector<uint32_t> node_index_vec;
        uint32_t index = 0;
        for (auto iter = shard_members_ptr->begin(); iter != shard_members_ptr->end(); ++iter) {
            if ((*iter)->pool_index_mod_num[0] >= 0) {
                tmp_leaders.push_back(*iter);
                node_index_vec.push_back(index++);
                if ((*iter)->id == common::GlobalInfo::Instance()->id()) {
                    local_node_pool_mod_num_ = (*iter)->pool_index_mod_num[0];
                    // create ecdh key
                }
            }

            if ((*iter)->id == common::GlobalInfo::Instance()->id()) {
                local_mem_ptr_[prev_elect_block.shard_network_id()] = *iter;
            }

            ELECT_DEBUG("DDDDDDDDDDDDDDDDDD ProcessNewElectBlock network: %d,"
                "member leader: %s,, (*iter)->pool_index_mod_num: %d",
                prev_elect_block.shard_network_id(),
                common::Encode::HexEncode((*iter)->id).c_str(),
                (*iter)->pool_index_mod_num[0]);
            std::cout << "DDDDDDDDDDDDDDDDDD ProcessNewElectBlock network: "
                << prev_elect_block.shard_network_id()
                << ", member leader: " << common::Encode::HexEncode((*iter)->id)
                << ", (*iter)->pool_index_mod_num: " << (*iter)->pool_index_mod_num[0]
                << ", leader count: " << prev_elect_block.leader_count()
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

        network_leaders_[prev_elect_block.shard_network_id()] = leaders;
    }

    if (*elected) {
        for (auto iter = shard_members_ptr->begin();
                iter != shard_members_ptr->end(); ++iter) {
            if ((*iter)->id != common::GlobalInfo::Instance()->id()) {
                security::EcdhCreateKey::Instance()->CreateKey(
                    (*iter)->pubkey,
                    (*iter)->backup_ecdh_key);
            }
        }

        for (auto iter = shard_members_ptr->begin();
                iter != shard_members_ptr->end(); ++iter) {
            if ((*iter)->id != common::GlobalInfo::Instance()->id()) {
                security::EcdhCreateKey::Instance()->CreateKey(
                    (*iter)->pubkey,
                    (*iter)->leader_ecdh_key);
            }
        }
    }

    members_ptr_[prev_elect_block.shard_network_id()] = shard_members_ptr;
    pool_manager_.NetworkMemberChange(prev_elect_block.shard_network_id(), shard_members_ptr);
    auto member_ptr = std::make_shared<MemberManager>();
    member_ptr->SetNetworkMember(
        prev_elect_block.shard_network_id(),
        shard_members_ptr,
        shard_members_index_ptr,
        prev_elect_block.leader_count());
    node_index_map_[prev_elect_block.shard_network_id()] = shard_members_index_ptr;
    mem_manager_ptr_[prev_elect_block.shard_network_id()] = member_ptr;
    {
        std::lock_guard<std::mutex> guard(valid_shard_networks_mutex_);
        valid_shard_networks_.insert(prev_elect_block.shard_network_id());
    }

    height_with_block_.AddNewHeightBlock(
        elect_block.prev_members().prev_elect_height(),
        prev_elect_block.shard_network_id(),
        shard_members_ptr);
    if (elect_net_heights_map_[prev_elect_block.shard_network_id()] == common::kInvalidUint64 ||
            elect_block.prev_members().prev_elect_height() >
            elect_net_heights_map_[prev_elect_block.shard_network_id()]) {
        elect_net_heights_map_[prev_elect_block.shard_network_id()] =
            elect_block.prev_members().prev_elect_height();
    }

    if (*elected) {
        UpdatePrevElectMembers(shard_members_ptr, elect_block);
    }
}

void ElectManager::ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool* elected) {
    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    auto& in = elect_block.in();
    auto shard_members_ptr = std::make_shared<Members>();
    uint32_t member_index = 0;
    for (int32_t i = 0; i < in.size(); ++i) {
        security::CommitSecret secret;
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        shard_members_ptr->push_back(std::make_shared<BftMember>(
            elect_block.shard_network_id(),
            id,
            in[i].pubkey(),
            member_index,
            in[i].dht_key(),
            in[i].pool_idx_mod_num()));
        AddNewNodeWithIdAndIp(elect_block.shard_network_id(), id, in[i].public_ip());
        if (id == common::GlobalInfo::Instance()->id()) {
            *elected = true;
        }

        ++member_index;
    }

    if (*elected) {
        bls::BlsManager::Instance()->ProcessNewElectBlock(height, shard_members_ptr);
    }
}

void ElectManager::UpdatePrevElectMembers(
        const elect::MembersPtr& members,
        protobuf::ElectBlock& elect_block) {
    if (members->size() != elect_block.prev_members().bls_pubkey_size()) {
        return;
    }

    auto t = common::GetSignerCount(members->size());
    int32_t i = 0;
    for (auto iter = members->begin(); iter != members->end(); ++iter, ++i) {
        std::vector<std::string> pkey_str = {
            elect_block.prev_members().bls_pubkey(i).x_c0(),
            elect_block.prev_members().bls_pubkey(i).x_c1(),
            elect_block.prev_members().bls_pubkey(i).y_c0(),
            elect_block.prev_members().bls_pubkey(i).y_c1()
        };

        BLSPublicKey pkey(
            std::make_shared<std::vector<std::string>>(pkey_str),
            t,
            members->size());
        (*iter)->bls_publick_key = *pkey.getPublicKey();
    }

    std::vector<std::string> pkey_str = {
            elect_block.prev_members().common_pubkey().x_c0(),
            elect_block.prev_members().common_pubkey().x_c1(),
            elect_block.prev_members().common_pubkey().y_c0(),
            elect_block.prev_members().common_pubkey().y_c1()
    };
    BLSPublicKey pkey(std::make_shared<std::vector<std::string>>(pkey_str), t, members->size());
    height_with_block_.SetCommonPublicKey(
        elect_block.prev_members().prev_elect_height(),
        elect_block.shard_network_id(),
        *pkey.getPublicKey());
    bls::BlsManager::Instance()->SetUsedElectionBlock(
        elect_block.prev_members().prev_elect_height(),
        elect_block.shard_network_id(),
        members->size(),
        *pkey.getPublicKey());
}

int ElectManager::BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.BackupCheckElectionBlockTx(local_tx_info, tx_info);
}

int ElectManager::CreateElectTransaction(
        uint32_t shard_netid,
        uint64_t final_statistic_block_height,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info) {
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        return kElectError;
    }

    return pool_manager_.CreateElectTransaction(
        shard_netid,
        final_statistic_block_height,
        src_tx_info,
        tx_info);
}

int ElectManager::GetElectionTxInfo(bft::protobuf::TxInfo& tx_info) {
    return pool_manager_.GetElectionTxInfo(tx_info);
}

uint64_t ElectManager::latest_height(uint32_t network_id) {
    if (network_id >= network::kConsensusShardEndNetworkId) {
        return common::kInvalidUint64;
    }

    return elect_net_heights_map_[network_id];
}

elect::MembersPtr ElectManager::GetNetworkMembersWithHeight(
        uint64_t elect_height,
        uint32_t network_id) {
    libff::alt_bn128_G2 common_pk;
    return height_with_block_.GetMembersPtr(elect_height, network_id, &common_pk);
}

uint32_t ElectManager::GetMemberCountWithHeight(uint64_t elect_height, uint32_t network_id) {
    auto members_ptr = GetNetworkMembersWithHeight(elect_height, network_id);
    if (members_ptr != nullptr) {
        return members_ptr->size();
    }

    return 0;
}

std::shared_ptr<MemberManager> ElectManager::GetMemberManager(uint32_t network_id) {
    return mem_manager_ptr_[network_id];
}

uint32_t ElectManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    if (node_index_map_[network_id] == nullptr) {
        return kInvalidMemberIndex;
    }

    auto iter = node_index_map_[network_id]->find(node_id);
    if (iter != node_index_map_[network_id]->end()) {
        return iter->second;
    }

    return kInvalidMemberIndex;
}

elect::MembersPtr ElectManager::GetNetworkMembers(uint32_t network_id) {
    return members_ptr_[network_id];
}

elect::BftMemberPtr ElectManager::GetMemberWithId(
        uint32_t network_id,
        const std::string& node_id) {
    auto mem_index = GetMemberIndex(network_id, node_id);
    if (mem_index == kInvalidMemberIndex) {
        return nullptr;
    }

    return GetMember(network_id, mem_index);
}

elect::BftMemberPtr ElectManager::GetMember(uint32_t network_id, uint32_t index) {
    if (network_id >= network::kConsensusShardEndNetworkId) {
        return nullptr;
    }

    if (index >= members_ptr_[network_id]->size()) {
        return nullptr;
    }

    return (*members_ptr_[network_id])[index];
}

uint32_t ElectManager::GetMemberCount(uint32_t network_id) {
    return latest_member_count_[network_id];
}

int32_t ElectManager::GetNetworkLeaderCount(uint32_t network_id) {
    return latest_leader_count_[network_id];
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
        added_net_id_set_[network_id].clear();
    }

    {
        std::lock_guard<std::mutex> guard(added_net_ip_set_mutex_);
        added_net_ip_set_[network_id].clear();
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

void ElectManager::ChangeInvalidLeader(uint32_t network_id, uint32_t leader_index) {
    // change invalid leader with 

}

}  // namespace elect

}  // namespace tenon
