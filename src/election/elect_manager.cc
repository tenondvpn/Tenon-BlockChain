#include "stdafx.h"
#include "election/elect_manager.h"

#include "common/utils.h"
#include "db/db_utils.h"
#include "dht/dht_utils.h"
#include "network/route.h"
#include "bft/bft_manager.h"

namespace tenon {

namespace elect {

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

    //LoadElectBlock();
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

void ElectManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kElectMessage);
    protobuf::ElectMessage ec_msg;
    if (!ec_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (ec_msg.has_elect_block()) {
        ProcessNewElectBlock(header, ec_msg, false);
        SaveElectBlock(header);
    }
}

void ElectManager::SaveElectBlock(transport::protobuf::Header& header) {
    std::string parse_str = header.SerializeAsString();
    db::Db::Instance()->Put(db::kGlobalDbElectBlock, parse_str);
}

void ElectManager::LoadElectBlock() {
    std::string parse_str;
    auto st = db::Db::Instance()->Get(db::kGlobalDbElectBlock, &parse_str);
    if (!st.ok()) {
        return;
    }
        
    transport::protobuf::Header header;
    if (!header.ParseFromString(parse_str)) {
        return;
    }

    protobuf::ElectMessage ec_msg;
    if (!ec_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (ec_msg.has_elect_block()) {
        ProcessNewElectBlock(header, ec_msg, true);
    }
}

void ElectManager::ProcessNewElectBlock(
        transport::protobuf::Header& header,
        protobuf::ElectMessage& elect_msg,
        bool load_from_db) {
    assert(elect_msg.has_elect_block());
    std::map<uint32_t, MembersPtr> in_members;
    std::map<uint32_t, MembersPtr> out_members;
    std::map<uint32_t, NodeIndexMapPtr> in_index_members;
    std::map<uint32_t, uint32_t> begin_index_map_;
    auto in = elect_msg.elect_block().in();
    for (int32_t i = 0; i < in.size(); ++i) {
        auto net_id = in[i].net_id();
        auto iter = in_members.find(net_id);
        if (iter == in_members.end()) {
            in_members[net_id] = std::make_shared<Members>();
            in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
            begin_index_map_[net_id] = 0;
        }
        security::PublicKey pubkey(in[i].pubkey());
        security::CommitSecret secret;
        in_members[net_id]->push_back(std::make_shared<BftMember>(
            net_id,
            in[i].id(),
            in[i].pubkey(),
            begin_index_map_[net_id],
            in[i].public_ip(),
            in[i].dht_key()));
        in_index_members[net_id]->insert(std::make_pair(in[i].id(), begin_index_map_[net_id]));
        if (load_from_db && in[i].has_public_ip()) {
            dht::NodePtr node = std::make_shared<dht::Node>(
                in[i].id(),
                in[i].dht_key(),
                in[i].nat_type(),
                false,
                in[i].public_ip(),
                in[i].public_port(),
                in[i].local_ip(),
                in[i].local_port(),
                in[i].pubkey(),
                "bft");
            node->join_com = "ProcessNewElectBlock";
            elect_node_ptr_->GetDht()->Join(node);
            network::UniversalManager::Instance()->AddNodeToUniversal(node);
        }

        ++begin_index_map_[net_id];
    }

    for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
        auto index_map_iter = in_index_members.find(iter->first);
        assert(index_map_iter != in_index_members.end());
        bft::BftManager::Instance()->NetworkMemberChange(
            iter->first,
            iter->second,
            index_map_iter->second);
    }
}

}  // namespace elect

}  // namespace tenon
