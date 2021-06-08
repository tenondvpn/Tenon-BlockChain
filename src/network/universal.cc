#include "stdafx.h"
#include "network/universal.h"

#include "common/global_info.h"
#include "common/state_lock.h"
#include "common/country_code.h"
#include "ip/ip_utils.h"
#include "ip/ip_with_country.h"
#include "transport/synchro_wait.h"
#include "dht/dht_key.h"
#include "dht/dht_function.h"
#include "dht/dht_function.h"
#include "network/network_utils.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/proto/network_proto.h"

namespace tenon {

namespace network {

Universal::Universal(transport::TransportPtr& transport_ptr, dht::NodePtr& local_node)
        : BaseDht(transport_ptr, local_node) {
}

Universal::~Universal() {
    Destroy();
}

int Universal::Init(
        dht::BootstrapResponseCallback boot_cb,
        dht::NewNodeJoinCallback node_join_cb) {
    if (BaseDht::Init(boot_cb, node_join_cb) != dht::kDhtSuccess) {
        NETWORK_ERROR("init base dht failed!");
        return kNetworkError;
    }

    universal_ids_ = new bool[kNetworkMaxDhtCount];
    std::fill(universal_ids_, universal_ids_ + kNetworkMaxDhtCount, false);

    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key());
    if (net_id == kUniversalNetworkId) {
        AddNetworkId(net_id);
    } else {
        dht::BaseDhtPtr dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
        if (dht) {
            auto universal_dht = std::dynamic_pointer_cast<Universal>(dht);
            if (universal_dht) {
                universal_dht->AddNetworkId(net_id);
            }
        }
    }
    return kNetworkSuccess;
}

bool Universal::CheckDestination(const std::string& des_dht_key, bool closest) {
    if (dht::BaseDht::CheckDestination(des_dht_key, closest)) {
        return true;
    }

    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(des_dht_key);
    if (!HasNetworkId(net_id)) {
        return false;
    }

    const auto& node = UniversalManager::Instance()->GetUniversal(net_id)->local_node();
    if (node->dht_key() != des_dht_key) {
        return false;
    }
    return true;
}

void Universal::SetFrequently(transport::protobuf::Header& msg) {
    dht::BaseDht::SetFrequently(msg);
    msg.set_universal(true);
}

std::vector<dht::NodePtr> Universal::LocalGetNetworkNodes(
        uint32_t network_id,
        uint32_t count) {
    return LocalGetNetworkNodes(
            network_id,
            ip::kInvalidCountryCode,
            count);
}

std::vector<dht::NodePtr> Universal::RemoteGetNetworkNodes(
        uint32_t network_id,
        uint32_t count) {
    return RemoteGetNetworkNodes(
            network_id,
            ip::kInvalidCountryCode,
            count);
}

std::vector<dht::NodePtr> Universal::LocalGetNetworkNodes(
        uint32_t network_id,
        uint8_t country,
        uint32_t count) {
    std::vector<dht::NodePtr> tmp_nodes;
    auto dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
    if (dht == nullptr) {
        return tmp_nodes;
    }

    auto local_nodes = *(dht->readonly_dht());  // change must copy
    local_nodes.push_back(dht->local_node());
    for (uint32_t i = 0; i < local_nodes.size(); ++i) {
        auto net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_nodes[i]->dht_key());
        uint8_t find_country = dht::DhtKeyManager::DhtKeyGetCountry(local_nodes[i]->dht_key());
        if (country == ip::kInvalidCountryCode) {
            if (net_id == network_id &&
                    local_nodes[i]->public_node) {
                tmp_nodes.push_back(local_nodes[i]);
            }
        } else {
            if (net_id == network_id &&
                    find_country == country &&
                    local_nodes[i]->public_node) {
                tmp_nodes.push_back(local_nodes[i]);
            }
        }
    }

    return tmp_nodes;
}

std::vector<dht::NodePtr> Universal::RemoteGetNetworkNodes(
        uint32_t network_id,
        uint8_t country,
        uint32_t count) {
    // may be can try 3 times for random destination dht key
    transport::protobuf::Header msg;
    SetFrequently(msg);
    NetworkProto::CreateGetNetworkNodesRequest(local_node(), network_id, country, count, msg);
    SendToClosestNode(msg);
    std::vector<dht::NodePtr> nodes;
    common::StateLock state_lock(1);
    auto callback = [&state_lock, &nodes](int status, transport::protobuf::Header& header) {
        do  {
            if (status != transport::kTransportSuccess) {
                break;
            }

            if (header.type() != common::kNetworkMessage) {
                break;
            }

            protobuf::NetworkMessage network_msg;
            if (!network_msg.ParseFromString(header.data())) {
                break;
            }

            if (!network_msg.has_get_net_nodes_res()) {
                break;
            }

            const auto& res_nodes = network_msg.get_net_nodes_res().nodes();
            for (int32_t i = 0; i < res_nodes.size(); ++i) {
                if (res_nodes[i].pubkey().empty()) {
                    continue;
                }

                auto node = std::make_shared<dht::Node>(
                        res_nodes[i].id(),
                        res_nodes[i].dht_key(),
                        res_nodes[i].nat_type(),
                        false,
                        res_nodes[i].public_ip(),
                        res_nodes[i].public_port(),
                        res_nodes[i].local_ip(),
                        res_nodes[i].local_port(),
                        res_nodes[i].pubkey(),
                        res_nodes[i].node_tag());
                node->min_svr_port = res_nodes[i].min_svr_port();
                node->max_svr_port = res_nodes[i].max_svr_port();
                node->min_route_port = res_nodes[i].min_route_port();
                node->max_route_port = res_nodes[i].max_route_port();
                nodes.push_back(node);
            }
        } while (0);
        state_lock.Signal();
    };
    transport::SynchroWait::Instance()->Add(msg.id(), 3 * 1000 * 1000, callback, 1);
    state_lock.Wait();
    return nodes;
}

void Universal::HandleMessage(transport::protobuf::Header& msg) {
    if (msg.type() == common::kDhtMessage || msg.type() == common::kNatMessage) {
        return dht::BaseDht::HandleMessage(msg);
    }

    if (msg.type() != common::kNetworkMessage) {
        return;
    }

    protobuf::NetworkMessage network_msg;
    if (!network_msg.ParseFromString(msg.data())) {
        DHT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    if (network_msg.has_get_net_nodes_req()) {
        ProcessGetNetworkNodesRequest(msg, network_msg);
    }

    if (network_msg.has_get_net_nodes_res()) {
        ProcessGetNetworkNodesResponse(msg, network_msg);
    }
}

void Universal::ProcessGetNetworkNodesRequest(
        transport::protobuf::Header& header,
        protobuf::NetworkMessage& network_msg) {
    std::vector<dht::NodePtr> nodes = LocalGetNetworkNodes(
            network_msg.get_net_nodes_req().net_id(),
            network_msg.get_net_nodes_req().country(),
            network_msg.get_net_nodes_req().count());
    if (nodes.empty()) {
        bool closest = false;
        {
            std::lock_guard<std::mutex> guard(dht_mutex_);
            if (dht::DhtFunction::IsClosest(
                    header.des_dht_key(),
                    local_node_->dht_key(),
                    dht_,
                    closest) != dht::kDhtSuccess) {
                SendToClosestNode(header);
            }
        }

        if (closest) {
            transport::protobuf::Header msg;
            SetFrequently(msg);
            NetworkProto::CreateGetNetworkNodesResponse(local_node_, header, nodes, msg);
            SendToClosestNode(msg);
            return;
        }

        SendToClosestNode(header);
        return;
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    NetworkProto::CreateGetNetworkNodesResponse(local_node_, header, nodes, msg);
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

void Universal::ProcessGetNetworkNodesResponse(
        transport::protobuf::Header& header,
        protobuf::NetworkMessage& network_msg) {
    if (header.des_dht_key() != local_node_->dht_key()) {
        SendToClosestNode(header);
        return;
    }

    transport::SynchroWait::Instance()->Callback(header.id(), header);
}

void Universal::AddNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    universal_ids_[network_id] = true;
}

void Universal::RemoveNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    universal_ids_[network_id] = false;
}

bool Universal::HasNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    return universal_ids_[network_id];
}

int Universal::Destroy() {
    if (universal_ids_ != nullptr) {
        delete []universal_ids_;
    }

    dht::BaseDhtPtr dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    if (dht == nullptr) {
        return kNetworkSuccess;
    }
    auto universal_dht = std::dynamic_pointer_cast<Universal>(dht);
    if (universal_dht == nullptr) {
        return kNetworkSuccess;
    }
    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key());
    universal_dht->RemoveNetworkId(net_id);
    return kNetworkSuccess;
}

}  // namespace network

}  //namespace tenon
