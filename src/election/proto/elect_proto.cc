#include "stdafx.h"
#include "election/proto/elect_proto.h"

#include <limits>

#include "common/country_code.h"
#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "dht/base_dht.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "election/proto/elect.pb.h"
#include "election/elect_utils.h"

namespace tenon {

namespace elect {

void ElectProto::SetDefaultBroadcastParam(
        transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(kElectBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kElectBroadcastStopTimes);
    broad_param->set_hop_limit(kElectHopLimit);
    broad_param->set_hop_to_layer(kElectHopToLayer);
    broad_param->set_neighbor_count(kElectNeighborCount);
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
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

}  // namespace elect

}  // namespace tenon
