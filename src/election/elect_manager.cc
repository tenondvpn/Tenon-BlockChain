#include "stdafx.h"
#include "election/elect_manager.h"

#include "common/utils.h"
#include "db/db_utils.h"
#include "dht/dht_utils.h"
#include "network/route.h"
#include "bft/bft_manager.h"
#include "security/secp256k1.h"
#include "election/proto/elect_proto.h"

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

    elect_node_ptr_ = std::make_shared<ElectNode>(network_id);
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
        return;
    }

    if (!security::IsValidSignature(ec_msg.sign_ch(), ec_msg.sign_res())) {
        return;
    }

    if (ec_msg.has_waiting_nodes()) {
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

        auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(ec_msg.pubkey());
        pool_manager_.UpdateWaitingNodes(
            ec_msg.waiting_nodes().waiting_shard_id(),
            id,
            fiter);
    }
}

void ElectManager::ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool load_from_db) {
    if (height < latest_height_) {
        return;
    }

    latest_height_ = height;
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
        security::PublicKey pubkey(in[i].pubkey());
        security::CommitSecret secret;
        auto id = security::Secp256k1::ToAddressWithPublicKey(in[i].pubkey());
        in_members[net_id]->push_back(std::make_shared<BftMember>(
            net_id,
            id,
            in[i].pubkey(),
            begin_index_map[net_id],
            in[i].public_ip(),
            in[i].public_port(),
            in[i].dht_key()));
        in_index_members[net_id]->insert(std::make_pair(in[i].id(), begin_index_map[net_id]));
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

        std::cout << "ProcessNewElectBlock id: " << common::Encode::HexEncode(id) << ", " << common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) << std::endl;
        if (in[i].id() == common::GlobalInfo::Instance()->id()) {
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
        MemberManager::Instance()->SetNetworkMember(
            iter->first,
            iter->second,
            index_map_iter->second);
    }
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

}  // namespace elect

}  // namespace tenon
