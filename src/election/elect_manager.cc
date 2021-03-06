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
#include "election/nodes_stoke_manager.h"
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
    ELECT_DEBUG("TTTTTTTTT ElectManager RegisterMessage called!");
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
            &ElectManager::NodeHasElected,
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
    ELECT_DEBUG("TTTTTT received elect message.");
    protobuf::ElectMessage ec_msg;
    if (!ec_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (ec_msg.has_sync_stoke_req()) {
        NodesStokeManager::Instance()->HandleSyncAddressStoke(header, ec_msg);
        return;
    }

    if (ec_msg.has_sync_stoke_res()) {
        NodesStokeManager::Instance()->HandleSyncStokeResponse(header, ec_msg);
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

    if (ec_msg.has_leader_rotation()) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(ec_msg.pubkey());
        auto mem_index = GetMemberIndex(
            common::GlobalInfo::Instance()->network_id(),
            id);
        if (mem_index == kInvalidMemberIndex) {
            return;
        }

        auto all_size = members_ptr_[common::GlobalInfo::Instance()->network_id()]->size();
        auto mem_ptr = GetMemberWithId(common::GlobalInfo::Instance()->network_id(), id);
        if (mem_ptr) {
            std::string hash_str = ec_msg.leader_rotation().leader_id() + 
                std::to_string(ec_msg.leader_rotation().pool_mod_num());
            auto message_hash = common::Hash::keccak256(hash_str);
            auto pubkey = security::PublicKey(ec_msg.pubkey());
            auto sign = security::Signature(ec_msg.sign_ch(), ec_msg.sign_res());
            if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
                ELECT_ERROR("leader rotation verify signature error.");
                return;
            }

            leader_rotation_.LeaderRotationReq(ec_msg.leader_rotation(), mem_index, all_size);
        }
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
                std::to_string(ec_msg.waiting_nodes().waiting_shard_id()) +
                ec_msg.waiting_nodes().stoke_hash();
            auto message_hash = common::Hash::keccak256(hash_str);
            auto pubkey = security::PublicKey(ec_msg.pubkey());
            auto sign = security::Signature(ec_msg.sign_ch(), ec_msg.sign_res());
            if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
                ELECT_ERROR("verify elect message signature failed!");
                return;
            }

            pool_manager_.UpdateWaitingNodes(
                ec_msg.waiting_nodes(),
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
                if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
                    ELECT_ERROR("verify signature failed!");
                    return;
                }

                auto elect_node_ptr = std::make_shared<ElectNodeDetail>();
                elect_node_ptr->public_ip = ip::IpToUint32(
                    ec_msg.waiting_heartbeat().public_ip().c_str(),
                    32);
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
    std::lock_guard<std::mutex> guard(elect_members_mutex_);
    if (elect_block.shard_network_id() >= network::kConsensusShardEndNetworkId ||
            elect_block.shard_network_id() < network::kRootCongressNetworkId) {
        return;
    }

    bool elected = false;
    now_elected_ids_.clear();
    bool cons_elect_valid = ProcessPrevElectMembers(elect_block, &elected);
    ProcessNewElectBlock(height, elect_block, &elected);
    if (!cons_elect_valid && !elected) {
        if (common::GlobalInfo::Instance()->network_id() == elect_block.shard_network_id()) {
            elected = true;
        }
    }

    ElectedToConsensusShard(elect_block, elected);
    pool_manager_.OnNewElectBlock(height, elect_block);
}

void ElectManager::ElectedToConsensusShard(protobuf::ElectBlock& elect_block, bool cons_elected) {
    auto local_netid = common::GlobalInfo::Instance()->network_id();
    if (!cons_elected) {
        if (local_netid == elect_block.shard_network_id()) {
//             Quit(local_netid);
            if (Join(local_netid + network::kConsensusWaitingShardOffset) != kElectSuccess) {
                BFT_ERROR("join elected network failed![%u]",
                    local_netid + network::kConsensusWaitingShardOffset);
            } else {
                BFT_INFO("join new election shard network: %u",
                    local_netid + network::kConsensusWaitingShardOffset);
            }
            common::GlobalInfo::Instance()->set_network_id(
                local_netid + network::kConsensusWaitingShardOffset);
        }
    } else {
        if (local_netid != elect_block.shard_network_id()) {
//             Quit(local_netid);
            if (Join(elect_block.shard_network_id()) != kElectSuccess) {
                BFT_ERROR("join elected network failed![%u]", elect_block.shard_network_id());
            } else {
                BFT_INFO("join new election shard network: %u", elect_block.shard_network_id());
            }
            common::GlobalInfo::Instance()->set_network_id(elect_block.shard_network_id());
        } else {
            std::vector<std::string> erase_nodes;
            for (auto iter = prev_elected_ids_.begin(); iter != prev_elected_ids_.end(); ++iter) {
                if (now_elected_ids_.find(*iter) != now_elected_ids_.end()) {
                    continue;
                }

                erase_nodes.push_back(*iter);
            }

            auto dht = network::DhtManager::Instance()->GetDht(local_netid);
            if (dht != nullptr) {
                dht->Drop(erase_nodes);
            }

            prev_elected_ids_ = now_elected_ids_;
        }
    }
}

bool ElectManager::ProcessPrevElectMembers(protobuf::ElectBlock& elect_block, bool* elected) {
    if (!elect_block.has_prev_members() || elect_block.prev_members().prev_elect_height() <= 0) {
        ELECT_DEBUG("not has prev members.");
        return false;
    }

//     std::cout << "ProcessPrevElectMembers now get prev block " << elect_block.prev_members().prev_elect_height() << std::endl;
    bft::protobuf::Block block_item;
    if (block::BlockManager::Instance()->GetBlockWithHeight(
            network::kRootCongressNetworkId,
            common::kRootChainPoolIndex,
            elect_block.prev_members().prev_elect_height(),
            block_item) != block::kBlockSuccess) {
        ELECT_ERROR("get prev block error[%d][%d][%lu].",
            network::kRootCongressNetworkId,
            common::kRootChainPoolIndex,
            elect_block.prev_members().prev_elect_height());
        return false;
    }

    if (block_item.tx_list_size() != 1) {
        ELECT_ERROR("not has tx list size.");
        return false;
    }

    elect::protobuf::ElectBlock prev_elect_block;
    bool ec_block_loaded = false;
    for (int32_t i = 0; i < block_item.tx_list(0).attr_size(); ++i) {
        if (block_item.tx_list(0).attr(i).key() == elect::kElectNodeAttrElectBlock) {
            prev_elect_block.ParseFromString(block_item.tx_list(0).attr(i).value());
            ec_block_loaded = true;
            break;
        }
    }

    if (!ec_block_loaded) {
        assert(false);
        return false;
    }

    if (added_height_.find(elect_block.prev_members().prev_elect_height()) != added_height_.end()) {
        ELECT_ERROR("height has added: %lu", elect_block.prev_members().prev_elect_height());
        return false;
    }

    added_height_.insert(elect_block.prev_members().prev_elect_height());
    latest_member_count_[prev_elect_block.shard_network_id()] = prev_elect_block.in_size();
    std::map<uint32_t, NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map;
    auto& in = prev_elect_block.in();
//     std::cout << "in member count: " << in.size() << std::endl;
    auto shard_members_ptr = std::make_shared<Members>();
    auto shard_members_index_ptr = std::make_shared<
        std::unordered_map<std::string, uint32_t>>();
    uint32_t member_index = 0;
    ClearExistsNetwork(prev_elect_block.shard_network_id());
    auto& prev_members_bls = elect_block.prev_members().bls_pubkey();
    if (prev_members_bls.size() != in.size()) {
        ELECT_ERROR("prev_members_bls.size(): %d, in.size(): %d, height: %lu",
            prev_members_bls.size(),
            in.size(),
            elect_block.prev_members().prev_elect_height());
        assert(false);
        return false;
    }

    uint32_t leader_count = 0;
    for (int32_t i = 0; i < in.size(); ++i) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        shard_members_ptr->push_back(std::make_shared<BftMember>(
            prev_elect_block.shard_network_id(),
            id,
            in[i].pubkey(),
            member_index,
            in[i].public_ip(),
            in[i].dht_key(),
            prev_members_bls[i].pool_idx_mod_num()));
        if (prev_members_bls[i].pool_idx_mod_num() >= 0) {
            ++leader_count;
        }

        AddNewNodeWithIdAndIp(prev_elect_block.shard_network_id(), id, in[i].public_ip());
        (*shard_members_index_ptr)[id] = member_index;
        ++member_index;
    }

    assert(leader_count > 0);
    latest_leader_count_[prev_elect_block.shard_network_id()] = leader_count;
    std::vector<std::string> pk_vec;
    UpdatePrevElectMembers(shard_members_ptr, elect_block, elected, &pk_vec);
    bool local_node_is_super_leader = false;
    {
        Members tmp_leaders;
        std::vector<uint32_t> node_index_vec;
        uint32_t index = 0;
        for (auto iter = shard_members_ptr->begin(); iter != shard_members_ptr->end(); ++iter) {
            if ((*iter)->pool_index_mod_num >= 0) {
                tmp_leaders.push_back(*iter);
                node_index_vec.push_back(index++);
            }

            now_elected_ids_.insert((*iter)->id);
            ELECT_INFO("DDDDDDDDDD elect height: %lu, network: %d,"
                "leader: %s, pool_index_mod_num: %d, valid pk: %d",
                elect_block.prev_members().prev_elect_height(),
                prev_elect_block.shard_network_id(),
                common::Encode::HexEncode((*iter)->id).c_str(),
                (*iter)->pool_index_mod_num,
                ((*iter)->bls_publick_key == libff::alt_bn128_G2::zero()));
//             std::cout << "DDDDDDDDDDDDDDDDDD ProcessNewElectBlock network: "
//                 << prev_elect_block.shard_network_id()
//                 << ", member leader: " << common::Encode::HexEncode((*iter)->id)
//                 << ", (*iter)->pool_index_mod_num: " << (*iter)->pool_index_mod_num
//                 << ", leader count: " << prev_elect_block.leader_count()
//                 << std::endl;
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
                local_node_is_super_leader = true;
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
    auto member_ptr = std::make_shared<MemberManager>();
    member_ptr->SetNetworkMember(
        prev_elect_block.shard_network_id(),
        shard_members_ptr,
        shard_members_index_ptr,
        leader_count);
    node_index_map_[prev_elect_block.shard_network_id()] = shard_members_index_ptr;
    mem_manager_ptr_[prev_elect_block.shard_network_id()] = member_ptr;
    {
        std::lock_guard<std::mutex> guard(valid_shard_networks_mutex_);
        valid_shard_networks_.insert(prev_elect_block.shard_network_id());
    }

    auto common_pk = BLSPublicKey(std::make_shared<std::vector<std::string>>(pk_vec));
    height_with_block_.AddNewHeightBlock(
        elect_block.prev_members().prev_elect_height(),
        prev_elect_block.shard_network_id(),
        shard_members_ptr,
        *common_pk.getPublicKey());
    if (elect_net_heights_map_[prev_elect_block.shard_network_id()] == common::kInvalidUint64 ||
            elect_block.prev_members().prev_elect_height() >
            elect_net_heights_map_[prev_elect_block.shard_network_id()]) {
        elect_net_heights_map_[prev_elect_block.shard_network_id()] =
            elect_block.prev_members().prev_elect_height();
        ELECT_DEBUG("set netid: %d, elect height: %lu",
            prev_elect_block.shard_network_id(), elect_block.prev_members().prev_elect_height());
    }

    if (prev_elect_block.shard_network_id() == common::GlobalInfo::Instance()->network_id() ||
            (prev_elect_block.shard_network_id() + network::kConsensusWaitingShardOffset) ==
            common::GlobalInfo::Instance()->network_id() || *elected) {
        leader_rotation_.OnElectBlock(shard_members_ptr);
        ELECT_DEBUG("set netid: %d, elect height: %lu, now net: %d, elected: %d",
            prev_elect_block.shard_network_id(),
            elect_block.prev_members().prev_elect_height(),
            common::GlobalInfo::Instance()->network_id(),
            *elected);
    }

    local_node_is_super_leader_ = local_node_is_super_leader;
    return true;
}

void ElectManager::ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool* elected) {
    auto& in = elect_block.in();
    auto shard_members_ptr = std::make_shared<Members>();
    uint32_t member_index = 0;
    if (elect_block.shard_network_id() == common::GlobalInfo::Instance()->network_id()) {
        local_waiting_node_member_index_ = kInvalidMemberIndex;
    }

    for (int32_t i = 0; i < in.size(); ++i) {
        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
        shard_members_ptr->push_back(std::make_shared<BftMember>(
            elect_block.shard_network_id(),
            id,
            in[i].pubkey(),
            member_index,
            in[i].public_ip(),
            in[i].dht_key(),
            in[i].pool_idx_mod_num()));
        AddNewNodeWithIdAndIp(elect_block.shard_network_id(), id, in[i].public_ip());
        if (id == common::GlobalInfo::Instance()->id()) {
            *elected = true;
            local_waiting_node_member_index_ = i;
        }

        now_elected_ids_.insert(id);
        ELECT_DEBUG("FFFFFFFFFFFFFFFFFFF ProcessNewElectBlock network: %d,"
            "member leader: %s,, (*iter)->pool_index_mod_num: %d, "
            "local_waiting_node_member_index_: %d",
            elect_block.shard_network_id(),
            common::Encode::HexEncode(id).c_str(),
            in[i].pool_idx_mod_num(),
            local_waiting_node_member_index_);
//         std::cout << "FFFFFFFFFFFFFFFFFFF ProcessNewElectBlock network: "
//             << elect_block.shard_network_id()
//             << ", member leader: " << common::Encode::HexEncode(id)
//             << ", (*iter)->pool_index_mod_num: " << in[i].pool_idx_mod_num()
//             << ", leader count: " << elect_block.leader_count()
//             << std::endl;

        ++member_index;
    }

    pool_manager_.NetworkMemberChange(elect_block.shard_network_id(), shard_members_ptr);
    waiting_members_ptr_[elect_block.shard_network_id()] = shard_members_ptr;
    waiting_elect_height_[elect_block.shard_network_id()] = height;
    bls::BlsManager::Instance()->ProcessNewElectBlock(
        *elected,
        elect_block.shard_network_id(),
        height,
        shard_members_ptr);
}

void ElectManager::UpdatePrevElectMembers(
        const elect::MembersPtr& members,
        protobuf::ElectBlock& elect_block,
        bool* elected,
        std::vector<std::string>* pkey_str_vect) {
//     std::cout << "DDDDDDDDDDDD " << members->size() << ":" << (uint32_t)elect_block.prev_members().bls_pubkey_size() << std::endl;
    if (members->size() != (uint32_t)elect_block.prev_members().bls_pubkey_size()) {
        return;
    }

    auto t = common::GetSignerCount(members->size());
    int32_t i = 0;
    for (auto iter = members->begin(); iter != members->end(); ++iter, ++i) {
        if ((*iter)->id == common::GlobalInfo::Instance()->id()) {
            local_node_member_index_ = i;
        }

        if (elect_block.prev_members().bls_pubkey(i).x_c0().empty()) {
            (*iter)->bls_publick_key = libff::alt_bn128_G2::zero();
            ELECT_DEBUG("get invalid bls public key index: %d, id: %s, elect height: %lu",
                i, common::Encode::HexEncode((*iter)->id).c_str(), elect_block.prev_members().prev_elect_height());
            continue;
        }

        std::vector<std::string> pkey_str = {
            elect_block.prev_members().bls_pubkey(i).x_c0(),
            elect_block.prev_members().bls_pubkey(i).x_c1(),
            elect_block.prev_members().bls_pubkey(i).y_c0(),
            elect_block.prev_members().bls_pubkey(i).y_c1()
        };

        if ((*iter)->id == common::GlobalInfo::Instance()->id()) {
            *elected = true;
        }

        BLS_DEBUG("id: %s, pk: %s,%s,%s,%s",
            common::Encode::HexEncode((*iter)->id).c_str(),
            elect_block.prev_members().bls_pubkey(i).x_c0().c_str(),
            elect_block.prev_members().bls_pubkey(i).x_c1().c_str(),
            elect_block.prev_members().bls_pubkey(i).y_c0().c_str(),
            elect_block.prev_members().bls_pubkey(i).y_c1().c_str());
//         std::cout << "set bls public key: " << i << ", " << elect_block.prev_members().bls_pubkey(i).x_c0()
//             << ", " << elect_block.prev_members().bls_pubkey(i).x_c1()
//             << ", " << elect_block.prev_members().bls_pubkey(i).y_c0()
//             << ", " << elect_block.prev_members().bls_pubkey(i).y_c1()
//             << std::endl;
        BLSPublicKey pkey(std::make_shared<std::vector<std::string>>(pkey_str));
        (*iter)->bls_publick_key = *pkey.getPublicKey();
    }

    *pkey_str_vect = std::vector<std::string>{
            elect_block.prev_members().common_pubkey().x_c0(),
            elect_block.prev_members().common_pubkey().x_c1(),
            elect_block.prev_members().common_pubkey().y_c0(),
            elect_block.prev_members().common_pubkey().y_c1()
    };

//     std::cout << "set common public key: " << i << ", " << elect_block.prev_members().common_pubkey().x_c0()
//         << ", " << elect_block.prev_members().common_pubkey().x_c1()
//         << ", " << elect_block.prev_members().common_pubkey().y_c0()
//         << ", " << elect_block.prev_members().common_pubkey().y_c1()
//         << std::endl;

    auto common_pk = BLSPublicKey(std::make_shared<std::vector<std::string>>(*pkey_str_vect));
    if (*elected) {
        bls::BlsManager::Instance()->SetUsedElectionBlock(
            elect_block.prev_members().prev_elect_height(),
            elect_block.shard_network_id(),
            members->size(),
            *common_pk.getPublicKey());
//         ELECT_DEBUG("use common public key: %s, %s, %s, %s",
//             elect_block.prev_members().common_pubkey().x_c0().c_str(),
//             elect_block.prev_members().common_pubkey().x_c1().c_str(),
//             elect_block.prev_members().common_pubkey().y_c0().c_str(),
//             elect_block.prev_members().common_pubkey().y_c1().c_str());
    }
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
        uint32_t network_id,
        libff::alt_bn128_G2* common_pk,
        libff::alt_bn128_Fr* sec_key) {
    return height_with_block_.GetMembersPtr(elect_height, network_id, common_pk, sec_key);
}

uint32_t ElectManager::GetMemberCountWithHeight(uint64_t elect_height, uint32_t network_id) {
    libff::alt_bn128_G2 common_pk;
    libff::alt_bn128_Fr sec_key;
    auto members_ptr = GetNetworkMembersWithHeight(
        elect_height,
        network_id,
        &common_pk,
        &sec_key);
    if (members_ptr != nullptr) {
        return members_ptr->size();
    }

    return 0;
}

std::shared_ptr<MemberManager> ElectManager::GetMemberManager(uint32_t network_id) {
    return mem_manager_ptr_[network_id];
}

uint32_t ElectManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    if (network_id >= network::kConsensusShardEndNetworkId || node_index_map_[network_id] == nullptr) {
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

elect::MembersPtr ElectManager::GetWaitingNetworkMembers(uint32_t network_id) {
    return waiting_members_ptr_[network_id];
}

bool ElectManager::NodeHasElected(uint32_t network_id, const std::string& node_id) {
    if (network_id < network::kRootCongressNetworkId ||
            network_id >= network::kConsensusShardEndNetworkId) {
        return false;
    }

    auto valid_members = members_ptr_[network_id];
    if (valid_members != nullptr) {
        for (auto iter = valid_members->begin(); iter != valid_members->end(); ++iter) {
            if ((*iter)->id == node_id) {
                return true;
            }
        }
    }

    auto waiting_members = waiting_members_ptr_[network_id];
    if (waiting_members != nullptr) {
        for (auto iter = waiting_members->begin(); iter != waiting_members->end(); ++iter) {
            if ((*iter)->id == node_id) {
                return true;
            }
        }
    }

    return false;
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

    auto mems_ptr = members_ptr_[network_id];
    if (mems_ptr == nullptr) {
        return nullptr;
    }

    if (index >= mems_ptr->size()) {
        return nullptr;
    }

    return (*mems_ptr)[index];
}

uint32_t ElectManager::GetMemberCount(uint32_t network_id) {
    return latest_member_count_[network_id];
}

int32_t ElectManager::GetNetworkLeaderCount(uint32_t network_id) {
    return latest_leader_count_[network_id];
}

void ElectManager::WaitingNodeSendHeartbeat() {
    if (common::GlobalInfo::Instance()->data_service_node_for_net_id() > 0) {
        return;
    }

    uint32_t net_id = common::GlobalInfo::Instance()->network_id();
    if (net_id >= network::kRootCongressWaitingNetworkId &&
            net_id < network::kConsensusWaitingShardEndNetworkId) {
        net_id -= network::kConsensusWaitingShardOffset;
    }

    bool joined = IsIdExistsInAnyShard(net_id, common::GlobalInfo::Instance()->id());
    if (!joined) {
        auto dht = network::DhtManager::Instance()->GetDht(
            common::GlobalInfo::Instance()->network_id());
        if (dht) {
            transport::protobuf::Header msg;
            elect::ElectProto::CreateWaitingHeartbeat(
                dht->local_node(),
                net_id + network::kConsensusWaitingShardOffset,
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

// bool ElectManager::IsIpExistsInAnyShard(uint32_t network_id, const std::string& ip) {
//     std::lock_guard<std::mutex> guard(added_net_ip_set_mutex_);
//     auto iter = added_net_ip_set_.find(network_id);
//     if (iter != added_net_id_set_.end()) {
//         return iter->second.find(ip) != iter->second.end();
//     }
// 
//     return false;
// }

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
        uint32_t ip) {
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
