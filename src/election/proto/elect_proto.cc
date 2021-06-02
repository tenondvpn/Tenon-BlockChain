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

void ElectProto::CreateElectBlock(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(4, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    auto dht = network::DhtManager::Instance()->GetDht(4);
	assert(dht);
    auto readonly_dht = dht->readonly_hash_sort_dht();
    if (readonly_dht.size() < 2) {
        return;
    }

    // now just for test
    protobuf::ElectMessage ec_msg;
    auto ec_block = ec_msg.mutable_elect_block();
    auto in = ec_block->add_in();
    in->set_id(local_node->id());
    in->set_pubkey(security::Schnorr::Instance()->str_pubkey());
    in->set_sign("sign");
    in->set_net_id(4);
    in->set_country(common::global_country_map["US"]);
    in->set_dht_key(local_node->dht_key());
    in->set_nat_type(local_node->nat_type);
    in->set_public_ip(local_node->public_ip());
    in->set_public_port(local_node->public_port);
    in->set_local_ip(local_node->local_ip());
    in->set_local_port(local_node->local_port);
    for (auto iter = readonly_dht.begin(); iter != readonly_dht.end(); ++iter) {
        auto in = ec_block->add_in();
        in->set_id((*iter)->id());
        in->set_pubkey((*iter)->pubkey_str());
        in->set_sign("sign");
        in->set_net_id(4);
        in->set_country(common::global_country_map["US"]);
        in->set_dht_key((*iter)->dht_key());
        in->set_nat_type((*iter)->nat_type);
        in->set_public_ip((*iter)->public_ip());
        in->set_public_port((*iter)->public_port);
        in->set_local_ip((*iter)->local_ip());
        in->set_local_port((*iter)->local_port);
    }

    ec_block->set_acc_pubkey("acc_pubkey");
    ec_block->set_acc_sign("acc_sign");

    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
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

    waiting_nodes_msg->set_waiting_shard_id(waiting_shard_id);
    ec_msg.set_pubkey("acc_pubkey");
    ec_msg.set_sign("acc_sign");
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
}

}  // namespace elect

}  // namespace tenon
