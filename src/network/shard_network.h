#pragma once

#include <functional>

#include "common/utils.h"
#include "common/string_utils.h"
#include "dht/dht_key.h"
#include "network/universal.h"
#include "network/network_utils.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/bootstrap.h"
#include "election/elect_dht.h"
#include "election/elect_node_detail.h"
#include "security/aes.h"
#include "security/ecdh_create_key.h"
#include "security/schnorr.h"

namespace tenon {

namespace network {

typedef std::function<elect::BftMemberPtr(
    uint32_t network_id,
    const std::string& node_id)> NetworkMemberCallback;

template<class DhtType>
class ShardNetwork {
public:
    ShardNetwork(uint32_t network_id, NetworkMemberCallback member_callback);
    ~ShardNetwork();
    int Init();
    void Destroy();
    dht::BaseDhtPtr GetDht() {
        return elect_dht_;
    }

private:
    int JoinUniversal();
    int JoinShard();
    int JoinNewNodeValid(dht::NodePtr& node);
    bool IsThisNetworkNode(uint32_t network_id, const std::string& id);
    int SignDhtMessage(
        const std::string& peer_pubkey,
        const std::string& append_data,
        std::string* enc_data,
        std::string* sign_ch,
        std::string* sign_re);

    dht::BaseDhtPtr universal_role_{ nullptr };
    dht::BaseDhtPtr elect_dht_{ nullptr };
    uint32_t network_id_{ network::kNetworkMaxDhtCount };
    transport::TransportPtr transport_{ nullptr };
    NetworkMemberCallback member_callback_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(ShardNetwork);
};

template<class DhtType>
ShardNetwork<DhtType>::ShardNetwork(
        uint32_t network_id,
        NetworkMemberCallback member_callback)
        : network_id_(network_id),
          member_callback_(member_callback) {
    common::GlobalInfo::Instance()->networks().push_back(network_id_);
}

template<class DhtType>
ShardNetwork<DhtType>::~ShardNetwork() {}

template<class DhtType>
int ShardNetwork<DhtType>::Init() {
    if (JoinShard() != kNetworkSuccess) {
        return kNetworkJoinShardFailed;
    }

    if (JoinUniversal() != kNetworkSuccess) {
        NETWORK_ERROR("create universal network failed!");
        return kNetworkJoinUniversalError;
    }

    return kNetworkSuccess;
}

template<class DhtType>
void ShardNetwork<DhtType>::Destroy() {
    if (universal_role_) {
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id_);
        universal_role_->Destroy();
        universal_role_.reset();
    }

    if (elect_dht_) {
        network::DhtManager::Instance()->UnRegisterDht(network_id_);
        elect_dht_->Destroy();
        elect_dht_.reset();
    }
}

// every one should join universal
template<class DhtType>
int ShardNetwork<DhtType>::JoinUniversal() {
    auto unversal_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(unversal_dht);
//     assert(unversal_dht->transport());
    assert(unversal_dht->local_node());
    auto local_node = std::make_shared<dht::Node>(*unversal_dht->local_node());
    uint8_t country = dht::DhtKeyManager::DhtKeyGetCountry(local_node->dht_key());
    dht::DhtKeyManager dht_key(network_id_, country, local_node->id());
    local_node->set_dht_key(dht_key.StrKey());
    local_node->dht_key_hash = common::Hash::Hash64(dht_key.StrKey());
    transport::TransportPtr tansport_ptr = unversal_dht->transport();
    universal_role_ = std::make_shared<network::Universal>(
        tansport_ptr,
        local_node);
    if (universal_role_->Init(
            nullptr,
            std::bind(
                &network::UniversalManager::AddNodeToUniversal,
                network::UniversalManager::Instance(),
                std::placeholders::_1)) != network::kNetworkSuccess) {
        NETWORK_ERROR("init universal role dht failed!");
        return kNetworkError;
    }

    network::UniversalManager::Instance()->RegisterUniversal(network_id_, universal_role_);
    if (universal_role_->Bootstrap(
            network::Bootstrap::Instance()->root_bootstrap()) != dht::kDhtSuccess) {
        NETWORK_ERROR("join universal network failed!");
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id_);
        return kNetworkError;
    }

    return kNetworkSuccess;
}

template<class DhtType>
bool ShardNetwork<DhtType>::IsThisNetworkNode(uint32_t network_id, const std::string& id) {
    if (network_id == common::GlobalInfo::Instance()->network_id() &&
            network_id >= network::kRootCongressNetworkId &&
            network_id < network::kConsensusShardEndNetworkId) {
        if (member_callback_ != nullptr) {
            if (member_callback_(network_id, id) != nullptr) {
                return true;
            }
        }
    }

    return true;
}

template<class DhtType>
int ShardNetwork<DhtType>::JoinNewNodeValid(dht::NodePtr& node) {
    if (!(network_id_ >= network::kRootCongressNetworkId &&
            network_id_ < network::kConsensusShardEndNetworkId)) {
        return dht::kDhtSuccess;
    }

    network::UniversalManager::Instance()->AddNodeToUniversal(node);
    auto network_id = dht::DhtKeyManager::DhtKeyGetNetId(node->dht_key());
    if (IsThisNetworkNode(network_id, node->id()) &&
            (node->join_way == dht::kJoinFromBootstrapReq ||
            node->join_way == dht::kJoinFromDetection ||
            node->join_way == dht::kJoinFromConnect)) {
        if (node->enc_data.empty() || node->enc_data.size() > 128) {
            return dht::kDhtError;
        }

        // check ecdh encrypt and decrypt valid, if not, can't join
        std::string sec_key;
        if (!security::IsValidPublicKey(node->pubkey_str())) {
            return dht::kDhtError;
        }

        security::PublicKey pubkey(node->pubkey_str());
        auto sign = security::Signature(node->sign_ch, node->sign_re);
        if (!security::Schnorr::Instance()->Verify(node->enc_data, sign, pubkey)) {
            return dht::kDhtError;
        }

        if (security::EcdhCreateKey::Instance()->CreateKey(
                pubkey,
                sec_key) != security::kSecuritySuccess) {
            return dht::kDhtError;
        }

        uint32_t data_size = 
            (node->enc_data.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
        char* tmp_out_enc = (char*)malloc(data_size);
        memset(tmp_out_enc, 0, data_size);
        if (security::Aes::Decrypt(
                (char*)node->enc_data.c_str(),
                node->enc_data.size(),
                (char*)sec_key.c_str(),
                sec_key.size(),
                tmp_out_enc) != security::kSecuritySuccess) {
            free(tmp_out_enc);
            return dht::kDhtError;
        }

        auto now_tm_sec = std::chrono::steady_clock::now().time_since_epoch().count() /
            1000000000llu;
        auto peer_tm_sec = common::StringUtil::ToUint64(tmp_out_enc);
        free(tmp_out_enc);
        if (now_tm_sec <= peer_tm_sec - 15 && now_tm_sec >= peer_tm_sec + 15) {
            return dht::kDhtError;
        }
    }

    return dht::kDhtSuccess;
}

template<class DhtType>
int ShardNetwork<DhtType>::JoinShard() {
    auto unversal_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(unversal_dht);
//     assert(unversal_dht->transport());
    assert(unversal_dht->local_node());
    auto local_node = std::make_shared<dht::Node>(*unversal_dht->local_node());
    uint8_t country = dht::DhtKeyManager::DhtKeyGetCountry(local_node->dht_key());
    dht::DhtKeyManager dht_key(network_id_, country, local_node->id());
    local_node->set_dht_key(dht_key.StrKey());
    local_node->dht_key_hash = common::Hash::Hash64(dht_key.StrKey());
    transport::TransportPtr tansport_ptr = unversal_dht->transport();
    elect_dht_ = std::make_shared<DhtType>(
        tansport_ptr,
        local_node);
    if (elect_dht_->Init(
            nullptr,
            std::bind(
                &ShardNetwork::JoinNewNodeValid,
                this,
                std::placeholders::_1)) != network::kNetworkSuccess) {
        NETWORK_ERROR("init shard role dht failed!");
        return kNetworkError;
    }

    elect_dht_->SetSignMessageCallback(std::bind(
        &dht::DefaultDhtSignCallback,
        std::placeholders::_1,
        std::placeholders::_2,
        std::placeholders::_3,
        std::placeholders::_4,
        std::placeholders::_5));
    network::DhtManager::Instance()->RegisterDht(network_id_, elect_dht_);
    auto boot_nodes = network::Bootstrap::Instance()->GetNetworkBootstrap(network_id_, 3);
    if (boot_nodes.empty()) {
        return kNetworkSuccess;
    }

    if (elect_dht_->Bootstrap(boot_nodes) != dht::kDhtSuccess) {
        NETWORK_ERROR("join shard network [%u] failed!", network_id_);
    }

    return kNetworkSuccess;
}

}  // namespace network

}  // namespace tenon
