#include "stdafx.h"
#include "network/proto/network_proto.h"

#include "common/global_info.h"
#include "common/encode.h"
#include "common/hash.h"
#include "ip/ip_utils.h"
#include "security/schnorr.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/proto/network.pb.h"

namespace tenon {

namespace network {

void NetworkProto::CreateGetNetworkNodesRequest(
        const dht::NodePtr& local_node,
        uint32_t network_id,
        uint32_t country,
        uint32_t count,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    auto tmp_country = country;
    if (tmp_country == ip::kInvalidCountryCode) {
        tmp_country = std::rand() % 255;
    }
    dht::DhtKeyManager dht_key(network_id, tmp_country, true);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kNetworkMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    network::protobuf::NetworkMessage net_msg;
    auto* get_nodes_req = net_msg.mutable_get_net_nodes_req();
    get_nodes_req->set_net_id(network_id);
    get_nodes_req->set_count(count);
    get_nodes_req->set_country(country);
    msg.set_data(net_msg.SerializeAsString());
}

void NetworkProto::CreateGetNetworkNodesResponse(
        const dht::NodePtr& local_node,
        const transport::protobuf::Header& header,
        const std::vector<dht::NodePtr>& nodes,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kNetworkMessage);
    msg.set_from_ip(header.from_ip());
    msg.set_from_port(header.from_port());
    msg.set_transport_type(header.transport_type());
    if (header.has_debug()) {
        msg.set_debug(header.debug());
    }

    if (header.client()) {
        msg.set_client(header.client());
        msg.set_client_relayed(true);
        msg.set_client_proxy(header.client_proxy());
        msg.set_client_dht_key(header.client_dht_key());
        msg.set_client_handled(true);
    }
    msg.set_hop_count(0);
    network::protobuf::NetworkMessage net_msg;
    auto* get_nodes_res = net_msg.mutable_get_net_nodes_res();
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i]->pubkey_str().empty()) {
            continue;
        }

        auto proto_node = get_nodes_res->add_nodes();
        proto_node->set_public_ip(nodes[i]->public_ip());
        proto_node->set_public_port(nodes[i]->public_port);
        proto_node->set_local_ip(nodes[i]->local_ip());
        proto_node->set_local_port(nodes[i]->local_port);
        proto_node->set_id(nodes[i]->id());
        proto_node->set_nat_type(nodes[i]->nat_type);
        proto_node->set_dht_key(nodes[i]->dht_key());
        proto_node->set_pubkey(nodes[i]->pubkey_str());
        proto_node->set_min_svr_port(nodes[i]->min_svr_port);
        proto_node->set_max_svr_port(nodes[i]->max_svr_port);
        proto_node->set_min_route_port(nodes[i]->min_route_port);
        proto_node->set_max_route_port(nodes[i]->max_route_port);
        proto_node->set_node_tag(nodes[i]->node_tag());
    }

    msg.set_data(net_msg.SerializeAsString());
}

}  // namespace network

}  // namespace tenon
