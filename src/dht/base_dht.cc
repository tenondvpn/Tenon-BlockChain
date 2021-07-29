#include "stdafx.h"
#include "dht/base_dht.h"

#include <stdio.h>

#include <bitset>
#include <algorithm>
#include <functional>
#include <limits>

#include "common/hash.h"
#include "common/encode.h"
#include "common/bloom_filter.h"
#include "common/country_code.h"
#include "common/time_utils.h"
#include "common/user_property_key_define.h"
#include "ip/ip_with_country.h"
#include "transport/processor.h"
#include "transport/transport_utils.h"
#include "transport/multi_thread.h"
#include "broadcast/broadcast_utils.h"
#include "nat_traverse/detection.h"
#include "dht/dht_utils.h"
#include "dht/proto/dht_proto.h"
#include "dht/dht_function.h"
#include "dht/dht_key.h"
#include "security/secp256k1.h"

namespace tenon {

namespace dht {

BaseDht::BaseDht(
        transport::TransportPtr& transport,
        NodePtr& local_node) : local_node_(local_node) {
}

BaseDht::~BaseDht() {}

int BaseDht::Init(BootstrapResponseCallback boot_cb, NewNodeJoinCallback node_join_cb) {
    bootstrap_response_cb_ = boot_cb;
    node_join_cb_ = node_join_cb;
    nat_detection_ = std::make_shared<nat::Detection>(shared_from_this());
    refresh_neighbors_tick_.CutOff(
            kRefreshNeighborPeriod,
            std::bind(&BaseDht::RefreshNeighbors, shared_from_this()));
    heartbeat_tick_.CutOff(
            kHeartbeatPeriod,
            std::bind(&BaseDht::Heartbeat, shared_from_this()));
    uint32_t net_id;
    uint8_t country;
    GetNetIdAndCountry(net_id, country);
    DHT_INFO("dht [%d][%d] init success.", net_id, country);
    return kDhtSuccess;
}

int BaseDht::Destroy() {
    refresh_neighbors_tick_.Destroy();
    heartbeat_tick_.Destroy();
    if (nat_detection_) {
        nat_detection_->Destroy();
    }
    return kDhtSuccess;
}

int BaseDht::Join(NodePtr& node) {
    if (node_join_cb_ != nullptr) {
        if (node_join_cb_(node) != kDhtSuccess) {
            return kDhtError;
        }
    }

    int res = CheckJoin(node);
    if (res != kDhtSuccess) {
        return res;
    }

    std::lock_guard<std::mutex> guard(dht_mutex_);
    std::unique_lock<std::mutex> lock_hash(node_map_mutex_);
    uint32_t b_dht_size = dht_.size();
    uint32_t b_map_size = node_map_.size();
    DhtFunction::PartialSort(local_node_->dht_key(), dht_.size(), dht_);
    uint32_t replace_pos = dht_.size() + 1;
    if (!DhtFunction::Displacement(local_node_->dht_key(), dht_, node, replace_pos)) {
        DHT_WARN("displacement for new node failed!");
        assert(false);
        return kDhtError;
    }

    if (replace_pos < dht_.size()) {
        auto rm_iter = dht_.begin() + replace_pos;
        auto hash_iter = node_map_.find((*rm_iter)->dht_key_hash);
        if (hash_iter != node_map_.end()) {
            node_map_.erase(hash_iter);
        }
        dht_.erase(rm_iter);
    }

    nat_detection_->Remove(node->dht_key_hash);
    auto iter = node_map_.insert(std::make_pair(node->dht_key_hash, node));
//     DHT_DEBUG("MMMMMMMM node_map_ size: %u", node_map_.size());
    if (!iter.second) {
        return kDhtNodeJoined;
    }

    dht_.push_back(node);
    std::sort(
            dht_.begin(),
            dht_.end(),
            [](const NodePtr& lhs, const NodePtr& rhs)->bool {
        return lhs->id_hash < rhs->id_hash;
    });
    {
        std::lock_guard<std::mutex> hash_dht_guard(readonly_hash_sort_dht_mutex_);
        readonly_hash_sort_dht_ = dht_;
    }

    if (node->node_tag() == common::kVpnVipNodeTag) {
        DHT_ERROR("vip node coming: %s", node->public_ip().c_str());
    }

    auto svr_port = common::GetVpnServerPort(node->dht_key(), common::TimeUtils::TimestampDays(), node->min_svr_port, node->max_svr_port);
    auto route_port = common::GetVpnServerPort(node->dht_key(), common::TimeUtils::TimestampDays(), node->min_route_port, node->max_route_port);
//     DHT_ERROR("join new node public ip: %s, dht key: %s, id: %s,"
//         "min_svr_port: %d, max_svr_port: %d, min_r_port: %d. max_r_port: %d., srv_port: %d, route_port: %d",
//         node->public_ip().c_str(),
//         common::Encode::HexEncode(node->dht_key()).c_str(),
//         common::Encode::HexEncode(node->id()).c_str(),
//         node->min_svr_port,
//         node->max_svr_port,
//         node->min_route_port,
//         node->max_route_port,
//         svr_port,
//         route_port);
//     uint32_t e_dht_size = dht_.size();
//     uint32_t e_map_size = node_map_.size();
//     assert((b_dht_size + 1) == e_dht_size);
//     assert((b_map_size + 1) == e_map_size);
//     assert(readonly_hash_sort_dht_->size() == e_map_size);
    return kDhtSuccess;
}

int BaseDht::Drop(NodePtr& node) {
    std::lock_guard<std::mutex> guard2(dht_mutex_);
    {
        if (dht_.size() <= kDhtMinReserveNodes) {
            return kDhtError;
        }

        auto& dht_key_hash = node->dht_key_hash;
        auto iter = std::find_if(
                dht_.begin(),
                dht_.end(),
                [dht_key_hash](const NodePtr& rhs) -> bool {
            return dht_key_hash == rhs->dht_key_hash;
        });
        if (iter != dht_.end()) {
            assert((*iter)->id() == node->id());
            dht_.erase(iter);
        }

        std::sort(
                dht_.begin(),
                dht_.end(),
                [](const NodePtr& lhs, const NodePtr& rhs)->bool {
            return lhs->id_hash < rhs->id_hash;
        });
        {
            std::lock_guard<std::mutex> hash_dht_guard(readonly_hash_sort_dht_mutex_);
            readonly_hash_sort_dht_ = dht_;
        }
    }

    {
        std::lock_guard<std::mutex> guard1(node_map_mutex_);
        auto iter = node_map_.find(node->dht_key_hash);
        if (iter != node_map_.end()) {
            assert(iter->second->id() == node->id());
            node_map_.erase(iter);
        }
    }
    return kDhtSuccess;
}

void BaseDht::SetFrequently(transport::protobuf::Header& message) {
    message.set_hop_count(0);
    message.set_src_node_id(local_node_->id());
    message.set_src_dht_key(local_node_->dht_key());
    message.set_priority(transport::kTransportPriorityLow);
    message.set_id(common::GlobalInfo::Instance()->MessageId());
    if (message.has_broadcast()) {
        auto broad_param = message.mutable_broadcast();
        broad_param->set_neighbor_count(broadcast::kBroadcastDefaultNeighborCount);
        broad_param->set_hop_limit(broadcast::kBroadcastHopLimit);
        broad_param->set_evil_rate(0);
        broad_param->set_hop_to_layer(broadcast::kBroadcastHopToLayer);
        broad_param->set_ign_bloomfilter_hop(broadcast::kBroadcastIgnBloomfilter);
    }
}

int BaseDht::Bootstrap(
        const std::vector<NodePtr>& boot_nodes,
        int32_t get_init_msg,
        const std::string init_uid) {
    assert(!boot_nodes.empty());
    for (uint32_t i = 0; i < boot_nodes.size(); ++i) {
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateBootstrapRequest(
            local_node_,
            boot_nodes[i],
            get_init_msg,
            init_uid,
            boot_nodes[i]->pubkey_str(),
            sign_msg_cb_, msg);
        // TODO(): fix local_port to public_port
        if (transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                    boot_nodes[i]->public_ip(),
                    boot_nodes[i]->local_port + 1,
                    0,
                    msg) != transport::kTransportSuccess) {
            DHT_ERROR("bootstrap from %s:%d failed\n",
                boot_nodes[i]->public_ip().c_str(),
                (boot_nodes[i]->local_port + 1));
        } else {
            DHT_ERROR("bootstrap from %s:%d success\n",
                boot_nodes[i]->public_ip().c_str(),
                (boot_nodes[i]->local_port + 1));
        }
    }

    std::unique_lock<std::mutex> lock(join_res_mutex_);
    join_res_con_.wait_for(lock, std::chrono::seconds(2), [this]() -> bool { return joined_; });
    if (!joined_) {
        DHT_WARN("join error.");
        return kDhtError;
    }
    return kDhtSuccess;
}

void BaseDht::SendToDesNetworkNodes(transport::protobuf::Header& message) {
    std::vector<NodePtr> closest_nodes;
    {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        closest_nodes = DhtFunction::GetClosestNodes(
            dht_,
            message.des_dht_key(),
            common::kDefaultBroadcastNeighborCount);
    }

    uint32_t send_count = 0;
    uint32_t des_net_id = DhtKeyManager::DhtKeyGetNetId(message.des_dht_key());
    for (auto iter = closest_nodes.begin(); iter != closest_nodes.end(); ++iter) {
        uint32_t net_id = DhtKeyManager::DhtKeyGetNetId((*iter)->dht_key());
        if (net_id != des_net_id) {
            continue;
        }

        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            (*iter)->public_ip(),
            (*iter)->local_port + 1,
            0,
            message);
        ++send_count;
    }

    if (send_count == 0) {
        SendToClosestNode(message);
    }
}

void BaseDht::SendToClosestNode(transport::protobuf::Header& message) {
    if (message.client_proxy() && message.client_handled()) {
        if (message.transport_type() == transport::kTcp) {
            transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                    message.from_ip(), message.from_port(), 0, message);
        } else {
            transport()->Send(message.from_ip(), message.from_port(), 0, message);
        }

        return;
    }

    if (message.des_dht_key() == local_node_->dht_key()) {
        DHT_ERROR("send to local dht key failed!");
        return;
    }

    std::vector<NodePtr> closest_nodes;
    {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        closest_nodes = DhtFunction::GetClosestNodes(
                dht_,
                message.des_dht_key(),
                kSendToClosestNodeCount);
    }

    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(message, "to close get node count: " + std::to_string(closest_nodes.size()));
    for (uint32_t i = 0; i < closest_nodes.size(); ++i) {
        if (closest_nodes[i]->public_ip() == local_node_->public_ip() &&
                closest_nodes[i]->local_port == local_node_->public_port) {
            Drop(closest_nodes[i]);
            continue;
        }

        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                closest_nodes[i]->public_ip(),
                closest_nodes[i]->local_port + 1,
                0,
                message);
        break;
    }
}

NodePtr BaseDht::FindNodeDirect(transport::protobuf::Header& message) {
    uint64_t des_dht_key_hash{ 0 };
    if (message.has_des_dht_key_hash()) {
        des_dht_key_hash = message.des_dht_key_hash();
    } else {
        des_dht_key_hash = common::Hash::Hash64(message.des_dht_key());
        message.set_des_dht_key_hash(des_dht_key_hash);
    }

    std::shared_ptr<std::unordered_map<uint64_t, NodePtr>> readony_node_map;
    auto iter = readony_node_map->find(des_dht_key_hash);
    if (iter == readony_node_map->end()) {
        return nullptr;
    }

    return iter->second;
}

void BaseDht::HandleMessage(const transport::protobuf::Header& header) {
    if (header.type() == common::kNatMessage) {
        return nat_detection_->HandleMessage(header);
    }

    if (header.type() != common::kDhtMessage) {
        DHT_ERROR("invalid message type[%d]", header.type());
        return;
    }

    protobuf::DhtMessage dht_msg;
    if (!dht_msg.ParseFromString(header.data())) {
        DHT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    DhtDispatchMessage(header, dht_msg);
}

void BaseDht::DhtDispatchMessage(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (dht_msg.has_bootstrap_req()) {
        ProcessBootstrapRequest(header, dht_msg);
    }

    if (dht_msg.has_bootstrap_res()) {
        ProcessBootstrapResponse(header, dht_msg);
    }

    if (dht_msg.has_refresh_neighbors_req()) {
        ProcessRefreshNeighborsRequest(header, dht_msg);
    }

    if (dht_msg.has_refresh_neighbors_res()) {
        ProcessRefreshNeighborsResponse(header, dht_msg);
    }

    if (dht_msg.has_heartbeat_req()) {
        ProcessHeartbeatRequest(header, dht_msg);
    }

    if (dht_msg.has_heartbeat_res()) {
        ProcessHeartbeatResponse(header, dht_msg);
    }

    if (dht_msg.has_connect_req()) {
        ProcessConnectRequest(header, dht_msg);
    }
}

void BaseDht::ProcessBootstrapRequest(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!dht_msg.has_bootstrap_req()) {
        DHT_WARN("dht message has no bootstrap request.");
        return;
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    std::string uid;
    if (dht_msg.bootstrap_req().has_uid()) {
        uid = dht_msg.bootstrap_req().uid();
    }

    DhtProto::CreateBootstrapResponse(
        dht_msg.bootstrap_req().node_id(),
        uid,
        dht_msg.bootstrap_req().get_init_msg(),
        local_node_,
        header,
        bootstrap_create_res_cb_,
        msg);
    uint16_t from_port = header.from_port();
    if (dht_msg.bootstrap_req().has_public_port() &&
            dht_msg.bootstrap_req().public_port() != 0) {
        from_port = dht_msg.bootstrap_req().public_port();
    } else {
        if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
            from_port -= 1;
        }
    }

    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), (from_port + 1), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), from_port, 0, msg);
    }

    if (header.client()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto src_dht_key = DhtKeyManager(header.src_dht_key());
    auto node_country = ip::IpWithCountry::Instance()->GetCountryUintCode(header.from_ip());
    if (node_country != ip::kInvalidCountryCode) {
        src_dht_key.SetCountryId(node_country);
    }

    NodePtr node = std::make_shared<Node>(
        dht_msg.bootstrap_req().node_id(),
        src_dht_key.StrKey(),
        dht_msg.bootstrap_req().nat_type(),
        header.client(),
        header.from_ip(),
        from_port,
        dht_msg.bootstrap_req().local_ip(),
        dht_msg.bootstrap_req().local_port(),
        header.pubkey(),
        dht_msg.bootstrap_req().node_tag());
    node->min_svr_port = dht_msg.bootstrap_req().min_svr_port();
    node->max_svr_port = dht_msg.bootstrap_req().max_svr_port();
    node->min_route_port = dht_msg.bootstrap_req().min_route_port();
    node->max_route_port = dht_msg.bootstrap_req().max_route_port();
    node->min_udp_port = dht_msg.bootstrap_req().min_udp_port();
    node->max_udp_port = dht_msg.bootstrap_req().max_udp_port();
    node->node_weight = dht_msg.bootstrap_req().node_weight();
    node->enc_data = dht_msg.enc_data();
    node->sign_ch = dht_msg.sign_ch();
    node->sign_re = dht_msg.sign_re();
    node->join_way = kJoinFromBootstrapReq;
    Join(node);
}

void BaseDht::ProcessBootstrapResponse(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("bootstrap request destination error[%s][%s]!",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key()).c_str());
        return;
    }

    if (!dht_msg.has_bootstrap_res()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign

    uint16_t from_port = header.from_port();
    if (dht_msg.bootstrap_res().has_peer_public_port() &&
            dht_msg.bootstrap_res().peer_public_port() != 0) {
        from_port = dht_msg.bootstrap_res().peer_public_port();
    } else {
        if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
            from_port -= 1;
        }
    }

    NodePtr node = std::make_shared<Node>(
            dht_msg.bootstrap_res().node_id(),
            header.src_dht_key(),
            dht_msg.bootstrap_res().nat_type(),
            false,
            header.from_ip(),
            from_port,
            dht_msg.bootstrap_res().local_ip(),
            static_cast<uint16_t>(dht_msg.bootstrap_res().local_port()),
            header.pubkey(),
            dht_msg.bootstrap_res().node_tag());
    node->min_svr_port = dht_msg.bootstrap_res().min_svr_port();
    node->max_svr_port = dht_msg.bootstrap_res().max_svr_port();
    node->min_route_port = dht_msg.bootstrap_res().min_route_port();
    node->max_route_port = dht_msg.bootstrap_res().max_route_port();
    node->min_udp_port = dht_msg.bootstrap_res().min_udp_port();
    node->max_udp_port = dht_msg.bootstrap_res().max_udp_port();
    node->node_weight = dht_msg.bootstrap_res().node_weight();
    node->join_way = kJoinFromBootstrapRes;
    Join(node);

    std::unique_lock<std::mutex> lock(join_res_mutex_);
    if (joined_) {
        return;
    }

    joined_ = true;
    join_res_con_.notify_one();
    local_node_->set_public_ip(dht_msg.bootstrap_res().public_ip());
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        local_node_->public_port = dht_msg.bootstrap_res().public_port() - 1;
    } else {
        local_node_->public_port = dht_msg.bootstrap_res().public_port();
    }

    if (common::GlobalInfo::Instance()->config_public_port() != 0) {
        local_node_->public_port = common::GlobalInfo::Instance()->config_public_port();
    }

    if (bootstrap_response_cb_ != nullptr) {
        // set global country
        bootstrap_response_cb_(this, dht_msg);
    }

    auto local_dht_key = DhtKeyManager(local_node_->dht_key());
    local_dht_key.SetCountryId(common::GlobalInfo::Instance()->country());
    local_node_->set_dht_key(local_dht_key.StrKey());
    local_node_->dht_key_hash = common::Hash::Hash64(local_node_->dht_key());
}

void BaseDht::ProcessRefreshNeighborsRequest(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!CheckDestination(header.des_dht_key(), false)) {
//         DHT_WARN("refresh neighbors request destnation error[%s][%s]"
//                 "from[%s][%d]to[%s][%d]",
//                 common::Encode::HexEncode(header.des_dht_key()).c_str(),
//                 common::Encode::HexEncode(local_node_->dht_key()).c_str(),
//                 header.from_ip().c_str(),
//                 header.from_port(),
//                 local_node_->public_ip().c_str(),
//                 local_node_->public_port);
        return;
    }

    if (!dht_msg.has_refresh_neighbors_req()) {
        DHT_WARN("not refresh neighbor request.");
        return;
    }
    std::vector<uint64_t> bloomfilter_vec;
    for (auto i = 0; i < dht_msg.refresh_neighbors_req().bloomfilter_size(); ++i) {
        bloomfilter_vec.push_back(dht_msg.refresh_neighbors_req().bloomfilter(i));
    }
    std::shared_ptr<common::BloomFilter> bloomfilter{ nullptr };
    if (!bloomfilter_vec.empty()) {
        bloomfilter = std::make_shared<common::BloomFilter>(
                bloomfilter_vec,
                kRefreshNeighborsBloomfilterHashCount);
    }

    Dht tmp_dht;
    if (bloomfilter) {
        std::vector<NodePtr> closest_nodes;
        {
            std::lock_guard<std::mutex> guard(dht_mutex_);
            closest_nodes = dht_;
        }

        for (auto iter = closest_nodes.begin(); iter != closest_nodes.end(); ++iter) {
            if (bloomfilter->Contain((*iter)->dht_key_hash)) {
                continue;
            }
            tmp_dht.push_back((*iter));
        }

        if (!bloomfilter->Contain(local_node_->dht_key_hash)) {
            tmp_dht.push_back(local_node_);
        }
    }
    auto close_nodes = DhtFunction::GetClosestNodes(
            tmp_dht,
            dht_msg.refresh_neighbors_req().des_dht_key(),
            kRefreshNeighborsDefaultCount + 1);
    if (close_nodes.empty()) {
        return;
    }

    transport::protobuf::Header res;
    SetFrequently(res);
    DhtProto::CreateRefreshNeighborsResponse(local_node_, header, close_nodes, res);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, res);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, res);
    }
}

void BaseDht::ProcessRefreshNeighborsResponse(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!CheckDestination(header.des_dht_key(), false)) {
//         DHT_WARN("refresh neighbors request destnation error[%s][%s]",
//                 common::Encode::HexEncode(header.des_dht_key()).c_str(),
//                 common::Encode::HexEncode(local_node_->dht_key()).c_str());
        return;
    }

    if (!dht_msg.has_refresh_neighbors_res()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    const auto& res_nodes = dht_msg.refresh_neighbors_res().nodes();
    for (int32_t i = 0; i < res_nodes.size(); ++i) {
        std::string node_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(
            res_nodes[i].public_key());
        NodePtr node = std::make_shared<Node>(
                node_id,
                res_nodes[i].dht_key(),
                res_nodes[i].nat_type(),
                false,
                res_nodes[i].public_ip(),
                res_nodes[i].public_port(),
                res_nodes[i].local_ip(),
                res_nodes[i].local_port(),
                res_nodes[i].public_key(),
                res_nodes[i].node_tag());
        node->min_svr_port = res_nodes[i].min_svr_port();
        node->max_svr_port = res_nodes[i].max_svr_port();
        node->min_route_port = res_nodes[i].min_route_port();
        node->max_route_port = res_nodes[i].max_route_port();
        node->min_udp_port = res_nodes[i].min_udp_port();
        node->max_udp_port = res_nodes[i].max_udp_port();
        node->node_weight = res_nodes[i].node_weight();
        transport::protobuf::Header msg;
        SetFrequently(msg);
        int res = CheckJoin(node);
        if (res != kDhtSuccess) {
            continue;
        }

        Join(node);
        if (DhtProto::CreateConnectRequest(
                local_node_,
                node,
                false,
                res_nodes[i].public_key(),
                sign_msg_cb_,
                msg) == kDhtSuccess) {
            // TODO(): fix local_port to public_port
            transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                    node->public_ip(), node->local_port + 1, 0, msg);
        }
    }
}

void BaseDht::AddDetectionTarget(NodePtr& node) {
    nat_detection_->AddTarget(node);
}

void BaseDht::ProcessHeartbeatRequest(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("ProcessHeartbeatRequest destnation error[%s][%s]",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key()).c_str());
        return;
    }

    if (!dht_msg.has_heartbeat_req()) {
        return;
    }

    NodePtr des_node = nullptr;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.find(dht_msg.heartbeat_req().dht_key_hash());
        if (iter != node_map_.end()) {
            iter->second->heartbeat_alive_times = kHeartbeatDefaultAliveTimes;
            iter->second->heartbeat_send_times = 0;
            des_node = iter->second;
        }
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    DhtProto::CreateHeatbeatResponse(local_node_, header, msg);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

void BaseDht::ProcessHeartbeatResponse(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("ProcessHeartbeatResponse destnation error[%s][%s]",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key()).c_str());
        return;
    }

    if (!dht_msg.has_heartbeat_res()) {
        return;
    }

    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.find(dht_msg.heartbeat_res().dht_key_hash());
        if (iter != node_map_.end()) {
            iter->second->heartbeat_alive_times = kHeartbeatDefaultAliveTimes;
            iter->second->heartbeat_send_times = 0;
        }
    }
}

void BaseDht::ProcessConnectRequest(
        const transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (header.des_dht_key() != local_node_->dht_key()) {
        if (dht_msg.connect_req().direct()) {
            return;
        }

        SendToClosestNode(header);
        return;
    }

    if (!dht_msg.has_connect_req()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }

    // check sign
    NodePtr node = std::make_shared<Node>(
            dht_msg.connect_req().id(),
            dht_msg.connect_req().dht_key(),
            dht_msg.connect_req().nat_type(),
            header.client(),
            dht_msg.connect_req().public_ip(),
            dht_msg.connect_req().public_port(),
            dht_msg.connect_req().local_ip(),
            static_cast<uint16_t>(dht_msg.connect_req().local_port()),
            header.pubkey(),
            dht_msg.connect_req().node_tag());
    node->min_svr_port = dht_msg.connect_req().min_svr_port();
    node->max_svr_port = dht_msg.connect_req().max_svr_port();
    node->min_route_port = dht_msg.connect_req().min_route_port();
    node->max_route_port = dht_msg.connect_req().max_route_port();
    node->min_udp_port = dht_msg.connect_req().min_udp_port();
    node->max_udp_port = dht_msg.connect_req().max_udp_port();
    node->node_weight = dht_msg.connect_req().node_weight();
    node->enc_data = dht_msg.enc_data();
    node->sign_ch = dht_msg.sign_ch();
    node->sign_re = dht_msg.sign_re();
    node->join_way = kJoinFromConnect;
    Join(node);
}

bool BaseDht::NodeValid(NodePtr& node) {
    if (node->dht_key().size() != kDhtKeySize) {
        DHT_ERROR("dht key size must[%u] now[%u]", kDhtKeySize, node->dht_key().size());
        return false;
    }

    if (node->public_ip().empty() || node->public_port <= 0) {
        DHT_ERROR("node[%s] public ip or port invalid!",
                common::Encode::HexEncode(node->id()).c_str());
        return false;
    }

    if (node->public_ip() == local_node_->public_ip() &&
            node->public_port == local_node_->public_port) {
        return false;
    }

    auto country_id = ip::IpWithCountry::Instance()->GetCountryUintCode(node->public_ip());
    auto dht_key_country_code = DhtKeyManager::DhtKeyGetCountry(node->dht_key());
    if (country_id != ip::kInvalidCountryCode) {
        if (country_id != dht_key_country_code) {
            DHT_ERROR("network id[%d] node public ip[%s] country [%d] not equal to node dht key country[%d]",
                    dht::DhtKeyManager::DhtKeyGetNetId(node->dht_key()),
                    node->public_ip().c_str(),
                    country_id,
                    dht_key_country_code);
            return false;
        }
    }
    return true;
}

bool BaseDht::NodeJoined(NodePtr& node) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    auto iter = node_map_.find(node->dht_key_hash);
    if (iter != node_map_.end()) {
        if (!node->node_tag().empty() && node->node_tag() != iter->second->node_tag()) {
            iter->second->set_node_tag(node->node_tag());
        }

        return true;
    }

    return false;
}

int BaseDht::CheckJoin(NodePtr& node) {
    if (node->public_ip() == "0.0.0.0" || common::IsVlanIp(node->public_ip())) {
        return kDhtIpInvalid;
    }

    if (node->pubkey_str().empty() || node->id().empty() || node->dht_key().empty()) {
        DHT_ERROR("invalid node nat type pubkey or id or dht key is empty.[%d][%d][%d][%d][%s:%d]",
                node->pubkey_str().empty(),
                node->id().empty(),
                node->dht_key().empty(),
                dht::DhtKeyManager::DhtKeyGetNetId(node->dht_key()),
                node->public_ip().c_str(),
                node->public_port);
        return kDhtKeyInvalid;
    }

    if (node->client_mode && !local_node_->client_mode) {
        return kDhtClientMode;
    }

    if (node->nat_type == kNatTypeUnknown) {
        DHT_ERROR("invalid node nat type.");
        return kDhtInvalidNat;
    }

    if (!NodeValid(node)) {
        return kNodeInvalid;
    }

    if (node->dht_key_hash == 0) {
        return kDhtKeyHashError;
    }

    if (node->dht_key_hash == local_node_->dht_key_hash) {
        DHT_ERROR("self join[%s][%s][%llu][%llu]",
                common::Encode::HexEncode(node->dht_key()).c_str(),
                common::Encode::HexEncode(local_node_->dht_key()).c_str(),
                node->dht_key_hash,
                local_node_->dht_key_hash);
        return kDhtKeyHashError;
    }

    if (node->dht_key() == local_node_->dht_key()) {
        return kDhtKeyHashError;
    }

    if (NodeJoined(node)) {
        return kDhtNodeJoined;
    }

    if (DhtFunction::GetDhtBucket(local_node_->dht_key(), node) != kDhtSuccess) {
        DHT_ERROR("compute node dht bucket index failed!");
        return kDhtGetBucketError;
    }

    std::unique_lock<std::mutex> lock(dht_mutex_);
    if (dht_.size() >= kDhtMaxNeighbors) {
        DhtFunction::PartialSort(local_node_->dht_key(), dht_.size(), dht_);
        uint32_t replace_pos = dht_.size() + 1;
        if (!DhtFunction::Displacement(local_node_->dht_key(), dht_, node, replace_pos)) {
//             DHT_ERROR("Displacement failed[%s]",
//                     common::Encode::HexEncode(node->id).c_str());
            return kDhtMaxNeiborsError;
        }
    }
    return kDhtSuccess;
}

bool BaseDht::CheckDestination(const std::string& des_dht_key, bool check_closest) {
    if (local_node_->client_mode) {
        return true;
    }

    if (des_dht_key == local_node_->dht_key()) {
        return true;
    }

    if (!check_closest) {
        return false;
    }

    bool closest = false;
    std::unique_lock<std::mutex> lock(dht_mutex_);
    if (DhtFunction::IsClosest(
            des_dht_key,
            local_node_->dht_key(),
            dht_,
            closest) != kDhtSuccess) {
        return false;
    }
    return closest;
}

void BaseDht::RefreshNeighbors() {
    std::vector<NodePtr> tmp_dht;
    {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        tmp_dht = dht_;
    }

    if (!tmp_dht.empty()) {
        auto close_nodes = DhtFunction::GetClosestNodes(
                tmp_dht,
                local_node_->dht_key(),
                16);
        auto rand_idx = std::rand() % close_nodes.size();
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateRefreshNeighborsRequest(
                tmp_dht,
                local_node_,
                close_nodes[rand_idx],
                msg);
        // TODO(): fix local_port to public_port
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                close_nodes[rand_idx]->public_ip(),
                close_nodes[rand_idx]->local_port + 1,
                0,
                msg);
    }

    if (local_node_->client_mode) {
        refresh_neighbors_tick_.CutOff(
                kRefreshNeighborPeriod * 10,
                std::bind(&BaseDht::RefreshNeighbors, shared_from_this()));
    } else {
        refresh_neighbors_tick_.CutOff(
                kRefreshNeighborPeriod,
                std::bind(&BaseDht::RefreshNeighbors, shared_from_this()));
    }
}

void BaseDht::Heartbeat() {
    return;
    std::vector<NodePtr> tmp_dht;
    {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        tmp_dht = dht_;
    }

    for (auto iter = tmp_dht.begin(); iter != tmp_dht.end(); ++iter) {
        auto node = (*iter);
        if (node == nullptr) {
            assert(false);
            continue;
        }

        if (node->heartbeat_send_times >= kHeartbeatMaxSendTimes) {
            Drop(node);
//             DHT_ERROR("heartbeat timeout[%d: %d], node[%s:%d]",
//                     node->heartbeat_send_times.fetch_add(0),
//                     kHeartbeatMaxSendTimes,
//                     node->public_ip.c_str(),
//                     (node->local_port + 1));
            continue;
        }

        if (node->heartbeat_alive_times > 0) {
            --(node->heartbeat_alive_times);
            continue;
        }

        int32_t rand_num = rand() % tmp_dht.size();
        if (rand_num > (int32_t)tmp_dht.size() / 5) {
            continue;
        }

        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateHeatbeatRequest(local_node_, *iter, msg);
        ++(node->heartbeat_send_times);
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                node->public_ip(), node->local_port + 1, 0, msg);
    }

    uint32_t net_id;
    uint8_t country;
    GetNetIdAndCountry(net_id, country);
    auto local_net_id = DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key());
    if (local_node_->client_mode) {
//         heartbeat_tick_.CutOff(
//                 kHeartbeatPeriod * 10,
//                 std::bind(&BaseDht::Heartbeat, shared_from_this()));
    } else {
        heartbeat_tick_.CutOff(
                kHeartbeatPeriod * 20,
                std::bind(&BaseDht::Heartbeat, shared_from_this()));
    }
}

void BaseDht::GetNetIdAndCountry(uint32_t& net_id, uint8_t& country) {
    net_id = DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key());
    country = DhtKeyManager::DhtKeyGetCountry(local_node_->dht_key());
}

}  // namespace dht

}  // namespace tenon
