#include "stdafx.h"
#include "network/universal_manager.h"

#include <cassert>

#include "common/global_info.h"
#include "common/encode.h"
#include "common/country_code.h"
#include "common/time_utils.h"
#include "ip/ip_with_country.h"
#include "security/schnorr.h"
#include "dht/dht_key.h"
#include "init/update_vpn_init.h"
#include "network/network_utils.h"
#include "network/bootstrap.h"

namespace tenon {

namespace network {

UniversalManager* UniversalManager::Instance() {
    static UniversalManager ins;
    return &ins;
}

void UniversalManager::Init() {
    if (dhts_ != nullptr) {
        return;
    }

    dhts_ = new dht::BaseDhtPtr[common::kNetworkMaxDhtCount];
    std::fill(dhts_, dhts_ + common::kNetworkMaxDhtCount, nullptr);
}

void UniversalManager::Destroy() {
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

void UniversalManager::RegisterUniversal(uint32_t network_id, dht::BaseDhtPtr& dht) {
    assert(network_id < common::kNetworkMaxDhtCount);
    assert(dhts_[network_id] == nullptr);
    dhts_[network_id] = dht;
}

void UniversalManager::UnRegisterUniversal(uint32_t network_id) {
    assert(network_id < common::kNetworkMaxDhtCount);
    if (dhts_[network_id] != nullptr) {
        dhts_[network_id]->Destroy();
        dhts_[network_id] = nullptr;
    }
}

dht::BaseDhtPtr UniversalManager::GetUniversal(uint32_t network_id) {
    assert(network_id < common::kNetworkMaxDhtCount);
    return dhts_[network_id];
}

void UniversalManager::DhtBootstrapResponseCallback(
        dht::BaseDht* dht_ptr,
        const dht::protobuf::DhtMessage& dht_msg) {
    if (dht_msg.bootstrap_res().has_init_message()) {
        init::UpdateVpnInit::Instance()->BootstrapInit(dht_msg.bootstrap_res().init_message());
    }

    auto local_node = dht_ptr->local_node();
    NETWORK_ERROR("get local public ip: %s, publc_port: %d, res public port: %d",
        local_node->public_ip().c_str(),
        local_node->public_port,
        dht_msg.bootstrap_res().public_port());
    auto net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node->dht_key());
    auto local_dht_key = dht::DhtKeyManager(local_node->dht_key());
    if (net_id == network::kUniversalNetworkId) {
        auto node_country = ip::IpWithCountry::Instance()->GetCountryUintCode(
            local_node->public_ip());
        if (node_country != ip::kInvalidCountryCode) {
            local_dht_key.SetCountryId(node_country);
        } else {
            auto server_country_code = dht_msg.bootstrap_res().country_code();
            if (server_country_code != ip::kInvalidCountryCode) {
                node_country = server_country_code;
                local_dht_key.SetCountryId(server_country_code);
            }
        }

        common::GlobalInfo::Instance()->set_country(node_country);
    }
}

int UniversalManager::CreateNetwork(
        uint32_t network_id,
        const common::Config& config,
        transport::TransportPtr& transport) {
    dht::DhtKeyManager dht_key(
        network_id,
        common::GlobalInfo::Instance()->country(),
        common::GlobalInfo::Instance()->id());
    bool client = false;
    config.Get("tenon", "client", client);
    dht::NodePtr local_node = std::make_shared<dht::Node>(
        common::GlobalInfo::Instance()->id(),
        dht_key.StrKey(),
        dht::kNatTypeFullcone,
        client,
        common::GlobalInfo::Instance()->config_local_ip(),
        common::GlobalInfo::Instance()->config_local_port(),
        common::GlobalInfo::Instance()->config_local_ip(),
        common::GlobalInfo::Instance()->config_local_port(),
        security::Schnorr::Instance()->str_pubkey(),
        common::GlobalInfo::Instance()->node_tag());
    local_node->first_node = common::GlobalInfo::Instance()->config_first_node();
    dht::BaseDhtPtr dht_ptr = std::make_shared<network::Universal>(transport, local_node);
    dht_ptr->Init(
        std::bind(
            &UniversalManager::DhtBootstrapResponseCallback,
            this,
            std::placeholders::_1,
            std::placeholders::_2),
        nullptr);
    dht_ptr->SetBootstrapResponseCreateCallback(std::bind(
        &init::UpdateVpnInit::GetInitMessage,
        init::UpdateVpnInit::Instance(),
        std::placeholders::_1,
        std::placeholders::_2,
        std::placeholders::_3,
        std::placeholders::_4));
    RegisterUniversal(network_id, dht_ptr);
    if (local_node->first_node) {
        return kNetworkSuccess;
    }

    std::vector<dht::NodePtr> boot_nodes;
    if (network_id == kUniversalNetworkId) {
        boot_nodes = Bootstrap::Instance()->root_bootstrap();
    } else {
        boot_nodes = Bootstrap::Instance()->node_bootstrap();
    }

    uint64_t bTime = common::TimeUtils::TimestampMs();
    int32_t get_init_msg = 0;
    std::string init_uid;
    config.Get("tenon", "init_uid", init_uid);
    config.Get("tenon", "get_init_msg", get_init_msg);
    if (dht_ptr->Bootstrap(boot_nodes, get_init_msg, init_uid) != dht::kDhtSuccess) {
//         UnRegisterUniversal(network_id);
        NETWORK_ERROR("bootstrap universal network failed!");
        return kNetworkError;
    }

    NETWORK_ERROR("dht_ptr->Bootstrap use time: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    return kNetworkSuccess;
}

int UniversalManager::CreateUniversalNetwork(
        const common::Config& config,
        transport::TransportPtr& transport) {
    int res = CreateNetwork(kUniversalNetworkId, config, transport);
    if (res != kNetworkSuccess) {
        return res;
    }

    auto universal_dht = GetUniversal(kUniversalNetworkId);
    if (universal_dht == nullptr) {
        return kNetworkError;
    }

    return kNetworkSuccess;
}

int UniversalManager::CreateNodeNetwork(
        const common::Config& config,
        transport::TransportPtr& transport) {
    return CreateNetwork(kNodeNetworkId, config, transport);
}

std::vector<dht::NodePtr> UniversalManager::GetSameNetworkNodes(
        uint32_t network_id,
        uint32_t count) {
    return Bootstrap::Instance()->GetNetworkBootstrap(network_id, count);
}

int UniversalManager::AddNodeToUniversal(dht::NodePtr& node) {
    auto universal_dht = GetUniversal(kUniversalNetworkId);
    if (universal_dht == nullptr) {
        return dht::kDhtSuccess;
    }

    node->join_way = dht::kJoinFromUnknown;
    int res = universal_dht->Join(node);
    return dht::kDhtSuccess;
}

UniversalManager::UniversalManager() {
    Init();
}

UniversalManager::~UniversalManager() {
    Destroy();
}

}  // namespace network

}  // namespace tenon
