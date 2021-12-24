#include "stdafx.h"
#include "network/dht_manager.h"

#include <cassert>
#include <algorithm>

#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "ip/ip_with_country.h"
#include "dht/proto/dht_proto.h"
#include "network/universal_manager.h"
#include "network/universal.h"

namespace tenon {

namespace network {

DhtManager* DhtManager::Instance() {
    static DhtManager ins;
    return &ins;
}

void DhtManager::Init() {
    dhts_ = new dht::BaseDhtPtr[common::kNetworkMaxDhtCount];
    std::fill(dhts_, dhts_ + common::kNetworkMaxDhtCount, nullptr);
    tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
}

void DhtManager::Destroy() {
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        dht_map_.clear();
    }

    if (dhts_ != nullptr) {
        for (uint32_t i = 0; i < common::kNetworkMaxDhtCount; ++i) {
            if (dhts_[i] != nullptr) {
                dhts_[i]->Destroy();
                dhts_[i] = nullptr;
            }
        }
        delete []dhts_;
        dhts_ = nullptr;
    }
}

void DhtManager::RegisterDht(uint32_t net_id, dht::BaseDhtPtr& dht) {
    assert(net_id < common::kNetworkMaxDhtCount);
//     assert(dhts_[net_id] == nullptr);
    if (dhts_[net_id] != nullptr) {
        NETWORK_DEBUG("dht has registered: %u", net_id);
        return;
    }

    dhts_[net_id] = dht;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        dht_map_[net_id] = dht;
    }
}

void DhtManager::UnRegisterDht(uint32_t net_id) {
    if (dhts_[net_id] == nullptr) {
        return;
    }

    assert(net_id < common::kNetworkMaxDhtCount);
    assert(dhts_[net_id] != nullptr);
    dhts_[net_id]->Destroy();
    dhts_[net_id] = nullptr;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        auto iter = dht_map_.find(net_id);
        if (iter != dht_map_.end()) {
            dht_map_.erase(iter);
        }
    }
}

dht::BaseDhtPtr DhtManager::GetDht(uint32_t net_id) {
    if (net_id >= common::kNetworkMaxDhtCount) {
        return nullptr;
    }

    return dhts_[net_id];
}

DhtManager::DhtManager() {
    Init();
}

DhtManager::~DhtManager() {
    Destroy();
}

void DhtManager::NetworkDetection() {
    std::vector<dht::BaseDhtPtr> detect_dhts;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        for (auto iter = dht_map_.begin(); iter != dht_map_.end(); ++iter) {
            if (iter->second->readonly_dht()->size() <= kNetworkDetectionLimitNum) {
                detect_dhts.push_back(iter->second);
            }
        }
    }

    auto dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    auto universal_dht = std::dynamic_pointer_cast<Universal>(dht);
    if (!universal_dht) {
        tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
        return;
    }

    for (auto iter = detect_dhts.begin(); iter != detect_dhts.end(); ++iter) {
        uint32_t network_id = dht::DhtKeyManager::DhtKeyGetNetId(
                (*iter)->local_node()->dht_key());
        auto nodes = universal_dht->LocalGetNetworkNodes(network_id, 4);
        NETWORK_DEBUG("detection network id: %d, nodes size: %d", network_id, nodes.size());
        if (nodes.empty()) {
            nodes = universal_dht->RemoteGetNetworkNodes(network_id, 4);
            NETWORK_DEBUG("detection network id: %d, remote nodes size: %d", network_id, nodes.size());
            if (nodes.empty()) {
                continue;
            }
        }

        auto node = nodes[std::rand() % nodes.size()];
        if (node->dht_key_hash == (*iter)->local_node()->dht_key_hash) {
            continue;
        }

        node->join_way = dht::kJoinFromNetworkDetection;
        int res = (*iter)->Join(node);
        network::UniversalManager::Instance()->AddNodeToUniversal(node);
        transport::protobuf::Header msg;
        (*iter)->SetFrequently(msg);
        // just connect
        dht::DhtProto::CreateConnectRequest(
            (*iter)->local_node(),
            node,
            true,
            node->pubkey_str(),
            dht::DefaultDhtSignCallback,
            msg);
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            node->public_ip(),
            node->local_port + 1,
            0,
            msg);
    }

    tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
}

}  // namespace network

}  // namespace tenon
