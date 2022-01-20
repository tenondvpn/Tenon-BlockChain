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
#include "security/schnorr.h"
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
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
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
    ec_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::CreateElectWaitingNodes(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
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

    std::string hash_str = nodes_filter.Serialize() + std::to_string(waiting_shard_id);
    waiting_nodes_msg->set_waiting_shard_id(waiting_shard_id);
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
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
    ec_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

void ElectProto::GetBlockZeroKnowledgeProof(
        const std::string& id,
        uint64_t random,
        uint32_t net_id,
        uint64_t max_height,
        uint64_t* max_zkp,
        uint64_t* rand_zkp) {
    uint64_t rerand = common::Hash::Hash64(id + std::to_string(random) + std::to_string(max_height));
    int32_t rand_pool = rerand % common::kInvalidPoolIndex;
    int32_t rand_height = rerand % max_height;
    std::string block_str;
    if (block::BlockManager::Instance()->GetBlockStringWithHeight(
            net_id,
            rand_pool,
            max_height,
            &block_str) != block::kBlockSuccess) {
        return;
    }

    if (block_str.size() < sizeof(uint64_t)) {
        return;
    }

    size_t rand_pos = rerand % (block_str.size() - sizeof(uint64_t));
    *max_zkp = ((uint64_t*)(block_str.c_str() + rand_pos))[0];

    std::string rand_block_str;
    if (block::BlockManager::Instance()->GetBlockStringWithHeight(
            net_id,
            rand_pool,
            max_height,
            &rand_block_str) != block::kBlockSuccess) {
        return;
    }

    if (rand_block_str.size() < sizeof(uint64_t)) {
        return;
    }

    rand_pos = rerand % (rand_block_str.size() - sizeof(uint64_t));
    *rand_zkp = ((uint64_t*)(rand_block_str.c_str() + rand_pos))[0];
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
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
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
    ec_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

}  // namespace elect

}  // namespace tenon
