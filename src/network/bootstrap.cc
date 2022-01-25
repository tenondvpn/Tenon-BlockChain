#include "stdafx.h"
#include "network/bootstrap.h"

#include "common/split.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "common/encode.h"
#include "dht/dht_key.h"
#include "security/crypto_utils.h"
#include "security/schnorr.h"
#include "network/network_utils.h"

namespace tenon {

namespace network {

Bootstrap* Bootstrap::Instance() {
    static Bootstrap ins;
    return &ins;
}

int Bootstrap::Init(common::Config& config) {
    std::string bootstrap;
    if (!config.Get("tenon", "bootstrap", bootstrap) || bootstrap.empty()) {
        NETWORK_ERROR("config has no tenon bootstrap info.");
        return kNetworkError;
    }

    std::string bootstrap_net;
    config.Get("tenon", "bootstrap_net", bootstrap_net) ;
    bootstrap += ',' + bootstrap_net;

    common::Split<2048> boot_spliter(bootstrap.c_str(), ',');
    std::set<std::string> boot_set;
    for (uint32_t i = 0; i < boot_spliter.Count(); ++i) {
        boot_set.insert(boot_spliter[i]);
        if (boot_set.size() >= 32) {
            break;
        }
    }

    bootstrap = "";
    for (auto iter = boot_set.begin(); iter != boot_set.end(); ++iter) {
        bootstrap += *iter + ",";
    }

    root_bootstrap_.clear();
    node_bootstrap_.clear();
    common::Split<2048> split(bootstrap.c_str(), ',', bootstrap.size());
    for (uint32_t i = 0; i < split.Count(); ++i) {
        common::Split<> field_split(split[i], ':', split.SubLen(i));
        if (field_split.Count() != 3) {
            continue;
        }
//         security::PrivateKey prikey;
//         security::PublicKey pubkey(prikey);
//         std::string str_pubkey;
//         if (pubkey.Serialize(str_pubkey) != security::kPublicKeySize) {
//             continue;
//         }

        tenon::dht::DhtKeyManager root_dht_key(
                kUniversalNetworkId,
                common::GlobalInfo::Instance()->country(),
                std::string(field_split[0], field_split.SubLen(0)));
        tenon::dht::DhtKeyManager node_dht_key(
                kNodeNetworkId,
                common::GlobalInfo::Instance()->country(),
                std::string(field_split[0], field_split.SubLen(0)));
        uint16_t port = 0;
        if (!tenon::common::StringUtil::ToUint16(field_split[2], &port)) {
            return kNetworkError;
        }

        root_bootstrap_.push_back(std::make_shared<tenon::dht::Node>(
            std::string(field_split[0], field_split.SubLen(0)),
            root_dht_key.StrKey(),
            std::string(field_split[1], field_split.SubLen(1)),
            port,
            security::Schnorr::Instance()->str_pubkey(),
            ""));
        node_bootstrap_.push_back(std::make_shared<tenon::dht::Node>(
            std::string(field_split[0], field_split.SubLen(0)),
            node_dht_key.StrKey(),
            std::string(field_split[1], field_split.SubLen(1)),
            port,
            security::Schnorr::Instance()->str_pubkey(),
            ""));
        NETWORK_INFO("bootstrap[%s][%d][%s][%s][%s]",
                field_split[0], field_split.SubLen(0), field_split[1], field_split[2],
                common::Encode::HexEncode(root_dht_key.StrKey()).c_str());
    }

    if (root_bootstrap_.empty() || node_bootstrap_.empty()) {
        return kNetworkError;
    }
    return kNetworkSuccess;
}

std::vector<dht::NodePtr> Bootstrap::GetNetworkBootstrap(
        uint32_t network_id,
        uint32_t count) {
    auto tmp_dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    std::shared_ptr<Universal> universal_dht = std::dynamic_pointer_cast<Universal>(tmp_dht);
    if (!universal_dht) {
        return std::vector<dht::NodePtr>();
    }

    auto nodes = universal_dht->LocalGetNetworkNodes(
            network_id,
            std::numeric_limits<uint8_t>::max(),
            count);
    if (!nodes.empty()) {
        return nodes;
    }

    nodes = universal_dht->RemoteGetNetworkNodes(network_id, count);
    return nodes;
}

}  // namespace network

}  // namespace tenon
