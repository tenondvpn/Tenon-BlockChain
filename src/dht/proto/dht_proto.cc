#include "stdafx.h"
#include "dht/proto/dht_proto.h"

#include "security/schnorr.h"
#include "ip/ip_with_country.h"
#include "init/update_vpn_init.h"
#include "dht/dht_key.h"

namespace tenon {

namespace dht {

void DhtProto::SetFreqMessage(BaseDhtPtr& dht, transport::protobuf::Header& msg) {
    assert(dht);
    dht->SetFrequently(msg);
}

void DhtProto::CreateBootstrapRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        int32_t get_init_msg,
        const std::string& init_uid,
        const std::string& peer_pubkey,
        VerifySignCallback sign_cb,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(des_node->dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto* bootstrap_req = dht_msg.mutable_bootstrap_req();
    bootstrap_req->set_uid(init_uid);
    bootstrap_req->set_local_ip(local_node->local_ip());
    bootstrap_req->set_local_port(local_node->local_port);
    bootstrap_req->set_node_id(common::GlobalInfo::Instance()->id());
    bootstrap_req->set_nat_type(local_node->nat_type);
    bootstrap_req->set_get_init_msg(get_init_msg);
    bootstrap_req->set_min_svr_port(common::GlobalInfo::Instance()->min_svr_port());
    bootstrap_req->set_max_svr_port(common::GlobalInfo::Instance()->max_svr_port());
    bootstrap_req->set_min_route_port(common::GlobalInfo::Instance()->min_route_port());
    bootstrap_req->set_max_route_port(common::GlobalInfo::Instance()->max_route_port());
    bootstrap_req->set_min_udp_port(common::GlobalInfo::Instance()->min_udp_port());
    bootstrap_req->set_max_udp_port(common::GlobalInfo::Instance()->max_udp_port());
    bootstrap_req->set_node_weight(common::GlobalInfo::Instance()->node_weight());
    bootstrap_req->set_version(common::GlobalInfo::Instance()->version());
    bootstrap_req->set_node_tag(common::GlobalInfo::Instance()->node_tag());
    if (common::GlobalInfo::Instance()->config_public_port() != 0) {
        bootstrap_req->set_public_port(common::GlobalInfo::Instance()->config_public_port());
    }

    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }

    if (sign_cb != nullptr) {
        std::string enc_data;
        std::string sign_ch;
        std::string sign_re;
        if (sign_cb(peer_pubkey, "", &enc_data, &sign_ch, &sign_re) != kDhtSuccess) {
            return;
        }

        dht_msg.set_enc_data(enc_data);
        dht_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        dht_msg.set_sign_ch(sign_ch);
        dht_msg.set_sign_re(sign_re);
    }

    msg.set_data(dht_msg.SerializeAsString());
}

void DhtProto::CreateBootstrapResponse(
        const std::string& id,
        const std::string& uid,
        int32_t get_init_msg,
        const NodePtr& local_node,
        const transport::protobuf::Header& header,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
    msg.set_hop_count(0);
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
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign
    dht::protobuf::DhtMessage res_dht_msg;
    auto* bootstrap_res = res_dht_msg.mutable_bootstrap_res();
    bootstrap_res->set_node_id(common::GlobalInfo::Instance()->id());
    bootstrap_res->set_nat_type(local_node->nat_type);
    bootstrap_res->set_local_ip(local_node->local_ip());
    bootstrap_res->set_local_port(local_node->local_port);
    bootstrap_res->set_public_ip(header.from_ip());
    bootstrap_res->set_public_port(header.from_port());
    bootstrap_res->set_min_svr_port(common::GlobalInfo::Instance()->min_svr_port());
    bootstrap_res->set_max_svr_port(common::GlobalInfo::Instance()->max_svr_port());
    bootstrap_res->set_min_route_port(common::GlobalInfo::Instance()->min_route_port());
    bootstrap_res->set_max_route_port(common::GlobalInfo::Instance()->max_route_port());
    bootstrap_res->set_min_udp_port(common::GlobalInfo::Instance()->min_udp_port());
    bootstrap_res->set_max_udp_port(common::GlobalInfo::Instance()->max_udp_port());
    bootstrap_res->set_node_weight(common::GlobalInfo::Instance()->node_weight());
    bootstrap_res->set_node_tag(common::GlobalInfo::Instance()->node_tag());
    if (common::GlobalInfo::Instance()->config_public_port() != 0) {
        bootstrap_res->set_peer_public_port(common::GlobalInfo::Instance()->config_public_port());
    }

    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        res_dht_msg.add_networks(*iter);
    }

    if (get_init_msg > 0) {
        auto& boot_init_msg = *(bootstrap_res->mutable_init_message());
        if (get_init_msg == dht::kBootstrapInitWithConfNodes) {
            boot_init_msg.set_use_conf_nodes(true);
        }

        init::UpdateVpnInit::Instance()->GetInitMessage(id, boot_init_msg, uid, header.version());
        DHT_ERROR("get boot init message called!");
    }

	auto node_country = ip::IpWithCountry::Instance()->GetCountryUintCode(header.from_ip());
	if (node_country != ip::kInvalidCountryCode) {
		bootstrap_res->set_country_code(node_country);
	} else {
		bootstrap_res->set_country_code(ip::kInvalidCountryCode);
	}

    msg.set_data(res_dht_msg.SerializeAsString());
}

void DhtProto::CreateRefreshNeighborsRequest(
        const Dht& dht,
        const NodePtr& local_node,
        const NodePtr& des_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(des_node->dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto refresh_nei_req = dht_msg.mutable_refresh_neighbors_req();
    refresh_nei_req->set_count(kRefreshNeighborsDefaultCount);
    common::BloomFilter bloomfilter{
            kRefreshNeighborsBloomfilterBitCount,
            kRefreshNeighborsBloomfilterHashCount };
    for (auto iter = dht.begin(); iter != dht.end(); ++iter) {
        bloomfilter.Add(common::Hash::Hash64((*iter)->dht_key()));
    }

    bloomfilter.Add(local_node->dht_key_hash);
    auto& bloomfilter_vec = bloomfilter.data();
    auto bloom_adder = refresh_nei_req->mutable_bloomfilter();
    for (uint32_t i = 0; i < bloomfilter_vec.size(); ++i) {
        bloom_adder->Add(bloomfilter_vec[i]);
    }
    refresh_nei_req->set_des_dht_key(local_node->dht_key());
    refresh_nei_req->set_count(dht.size() + 1);
    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }

    msg.set_data(dht_msg.SerializeAsString());
}

void DhtProto::CreateRefreshNeighborsResponse(
        const NodePtr& local_node,
        const transport::protobuf::Header& header,
        const std::vector<NodePtr>& nodes,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
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
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto refresh_nei_res = dht_msg.mutable_refresh_neighbors_res();
    auto res_cnt = nodes.size();
    if (res_cnt > kRefreshNeighborsDefaultCount) {
        res_cnt = kRefreshNeighborsDefaultCount;
    }

    for (uint32_t i = 0; i < res_cnt; ++i) {
        auto proto_node = refresh_nei_res->add_nodes();
        proto_node->set_public_ip(nodes[i]->public_ip());
        proto_node->set_public_port(nodes[i]->public_port);
        proto_node->set_local_ip(nodes[i]->local_ip());
        proto_node->set_local_port(nodes[i]->local_port);
        proto_node->set_public_key(nodes[i]->pubkey_str());
        proto_node->set_nat_type(nodes[i]->nat_type);
        proto_node->set_dht_key(nodes[i]->dht_key());
        proto_node->set_min_svr_port(nodes[i]->min_svr_port);
        proto_node->set_max_svr_port(nodes[i]->max_svr_port);
        proto_node->set_min_route_port(nodes[i]->min_route_port);
        proto_node->set_max_route_port(nodes[i]->max_route_port);
        proto_node->set_min_udp_port(nodes[i]->min_udp_port);
        proto_node->set_max_udp_port(nodes[i]->min_udp_port);
        proto_node->set_node_tag(nodes[i]->node_tag());
    }

    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }
    msg.set_data(dht_msg.SerializeAsString());
}

void DhtProto::CreateHeatbeatRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(des_node->dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    dht::protobuf::DhtMessage dht_msg;
    auto heartbeat_req = dht_msg.mutable_heartbeat_req();
    heartbeat_req->set_dht_key_hash(local_node->dht_key_hash);
    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }

    msg.set_data(dht_msg.SerializeAsString());
}

void DhtProto::CreateHeatbeatResponse(
        const NodePtr& local_node,
        transport::protobuf::Header& header,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
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
    dht::protobuf::DhtMessage dht_msg;
    auto heartbeat_res = dht_msg.mutable_heartbeat_res();
    heartbeat_res->set_dht_key_hash(local_node->dht_key_hash);
    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }

    msg.set_data(dht_msg.SerializeAsString());
}

int32_t DhtProto::CreateConnectRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        bool direct,
        const std::string& peer_pubkey,
        VerifySignCallback sign_cb,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(des_node->dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_des_dht_key_hash(des_node->dht_key_hash);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto connect_req = dht_msg.mutable_connect_req();
    if (common::IsVlanIp(local_node->public_ip())) {
        return kDhtError;
    }

    connect_req->set_public_ip(local_node->public_ip());
    connect_req->set_public_port(local_node->public_port);
    connect_req->set_local_ip(local_node->local_ip());
    connect_req->set_local_port(local_node->local_port);
    connect_req->set_nat_type(local_node->nat_type);
    connect_req->set_id(local_node->id());
    connect_req->set_dht_key(local_node->dht_key());
    connect_req->set_direct(direct);
    connect_req->set_min_svr_port(common::GlobalInfo::Instance()->min_svr_port());
    connect_req->set_max_svr_port(common::GlobalInfo::Instance()->max_svr_port());
    connect_req->set_min_route_port(common::GlobalInfo::Instance()->min_route_port());
    connect_req->set_max_route_port(common::GlobalInfo::Instance()->max_route_port());
    connect_req->set_min_udp_port(common::GlobalInfo::Instance()->min_udp_port());
    connect_req->set_max_udp_port(common::GlobalInfo::Instance()->max_udp_port());
    connect_req->set_node_weight(common::GlobalInfo::Instance()->node_weight());
    connect_req->set_node_tag(common::GlobalInfo::Instance()->node_tag());
    auto& networks = common::GlobalInfo::Instance()->networks();
    for (auto iter = networks.begin(); iter != networks.end(); ++iter) {
        dht_msg.add_networks(*iter);
    }

    if (sign_cb != nullptr) {
        std::string enc_data;
        std::string sign_ch;
        std::string sign_re;
        if (sign_cb(peer_pubkey, "", &enc_data, &sign_ch, &sign_re) != kDhtSuccess) {
            return kDhtError;
        }

        dht_msg.set_enc_data(enc_data);
        dht_msg.set_sign_ch(sign_ch);
        dht_msg.set_sign_re(sign_re);
    }

    msg.set_data(dht_msg.SerializeAsString());
    return kDhtSuccess;
}

}  // namespace dht

}  //namespace tenon

