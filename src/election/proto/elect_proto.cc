#include "stdafx.h"
#include "election/proto/elect_proto.h"

#include <limits>

#include "block/block_manager.h"
#include "common/country_code.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "common/time_utils.h"
#include "dht/dht_key.h"
#include "dht/base_dht.h"
#include "election/proto/elect.pb.h"
#include "election/elect_utils.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "security/security.h"
#include "timeblock/time_block_manager.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace elect {

void ElectProto::CreateLeaderRotation(
        const dht::NodePtr& local_node,
        const std::string& leader_id,
        uint32_t pool_mod_num,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(common::GlobalInfo::Instance()->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(false);
    msg.set_universal(false);
    msg.set_hop_count(0);

    // now just for test
    protobuf::ElectMessage ec_msg;
    auto leader_rotation = ec_msg.mutable_leader_rotation();
    leader_rotation->set_leader_id(leader_id);
    leader_rotation->set_pool_mod_num(pool_mod_num);
    std::string hash_str = leader_id + std::to_string(pool_mod_num);
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Security::Instance()->Sign(
        message_hash,
        *(security::Security::Instance()->prikey()),
        *(security::Security::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        ELECT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    ec_msg.set_sign_ch(sign_challenge_str);
    ec_msg.set_sign_res(sign_response_str);
    ec_msg.set_pubkey(security::Security::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::CreateElectWaitingNodes(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
        const std::string& balance_hash_256,
        const common::BloomFilter& nodes_filter,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);

    // now just for test
    protobuf::ElectMessage ec_msg;
    auto waiting_nodes_msg = ec_msg.mutable_waiting_nodes();
    for (uint32_t i = 0; i < nodes_filter.data().size(); ++i) {
        waiting_nodes_msg->add_nodes_filter(nodes_filter.data()[i]);
    }

    waiting_nodes_msg->set_stoke_hash(balance_hash_256);
    std::string hash_str = nodes_filter.Serialize() +
        std::to_string(waiting_shard_id) +
        balance_hash_256;
    waiting_nodes_msg->set_waiting_shard_id(waiting_shard_id);
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Security::Instance()->Sign(
        message_hash,
        *(security::Security::Instance()->prikey()),
        *(security::Security::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        ELECT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    ec_msg.set_sign_ch(sign_challenge_str);
    ec_msg.set_sign_res(sign_response_str);
    ec_msg.set_pubkey(security::Security::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::CreateWaitingHeartbeat(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);

    // now just for test
    protobuf::ElectMessage ec_msg;
    auto heartbeat_msg = ec_msg.mutable_waiting_heartbeat();
    heartbeat_msg->set_public_ip(local_node->public_ip());
    heartbeat_msg->set_public_port(local_node->public_port);
    heartbeat_msg->set_network_id(waiting_shard_id);
    heartbeat_msg->set_timestamp_sec(common::TimeUtils::TimestampSeconds());
    auto message_hash = GetElectHeartbeatHash(
        ec_msg.waiting_heartbeat().public_ip(),
        ec_msg.waiting_heartbeat().public_port(),
        ec_msg.waiting_heartbeat().network_id(),
        ec_msg.waiting_heartbeat().timestamp_sec());
    security::Signature sign;
    bool sign_res = security::Security::Instance()->Sign(
        message_hash,
        *(security::Security::Instance()->prikey()),
        *(security::Security::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        ELECT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    ec_msg.set_sign_ch(sign_challenge_str);
    ec_msg.set_sign_res(sign_response_str);
    ec_msg.set_pubkey(security::Security::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::CreateSyncStokeRequest(
        const dht::NodePtr& local_node,
        uint32_t des_net_id,
        const std::vector<std::pair<std::string, uint64_t>>& ids,
        transport::protobuf::Header& msg) {
    // check if has waiting nodes to get account balance
    //  + network::kConsensusWaitingShardOffset
    auto tmp_net_id = des_net_id + network::kConsensusWaitingShardOffset;
    auto dht = network::DhtManager::Instance()->GetDht(tmp_net_id);
    if (dht != nullptr) {
        des_net_id = tmp_net_id;
    }

    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);

    // now just for test
    protobuf::ElectMessage ec_msg;
    auto sync_stoke_req = ec_msg.mutable_sync_stoke_req();
    sync_stoke_req->set_now_tm_height(
        tmblock::TimeBlockManager::Instance()->LatestTimestampHeight());
    for (auto iter = ids.begin(); iter != ids.end(); ++iter) {
        auto stoke_item = sync_stoke_req->add_sync_item();
        stoke_item->set_id((*iter).first);
        stoke_item->set_synced_tm_height((*iter).second);
    }

    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::CreateSyncStokeResponse(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg) {

}


}  // namespace elect

}  // namespace tenon
