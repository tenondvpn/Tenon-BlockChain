#include "stdafx.h"
#include "init/update_vpn_init.h"

#include <memory>

#include "common/country_code.h"
#include "common/time_utils.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "common/state_lock.h"
#include "ip/ip_with_country.h"
#include "dht/dht_key.h"
#include "db/db.h"
#include "db/db_utils.h"
#include "block/proto/block.pb.h"
#include "transport/synchro_wait.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/ecdh_create_key.h"
#include "security/secp256k1.h"
#include "network/route.h"
#include "network/network_utils.h"
#include "network/universal.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "bft/bft_utils.h"
#ifdef _WIN32
#define MAKE_CLIENT_LIB
#endif
#include "security/schnorr.h"


namespace tenon {

namespace init {

UpdateVpnInit* UpdateVpnInit::Instance() {
    static UpdateVpnInit ins;
    return &ins;
}

UpdateVpnInit::UpdateVpnInit() {}

UpdateVpnInit::~UpdateVpnInit() {}
// bd5e14099f61c4a1caea7f7e677=
void UpdateVpnInit::ServerInit(const common::Config& conf) {
#ifdef ENABLE_CLIENT_MODE
    {
        std::string cns;
        if (!conf.Get("tenon", "cns", cns) || cns.empty()) {
            cns = "AU,CA,CN,DE,FR,GB,HK,IN,JP,NL,SG,US,PH,KR,ID";
        }

        common::Split<> country_split(cns.c_str(), ',', cns.size());
        std::lock_guard<std::mutex> guard(country_vec_mutex_);
        country_vec_.clear();
        for (uint32_t cnt_idx = 0; cnt_idx < country_split.Count(); ++cnt_idx) {
            if (country_split.SubLen(cnt_idx) == 2) {
                country_vec_.push_back(country_split[cnt_idx]);
            }
        }
    }
    std::string config_nodes;
    conf.Get("tenon", "config_nodes", config_nodes);
    if (!config_nodes.empty()) {
        common::Split<1024> nodes_split(config_nodes.c_str(), ',', config_nodes.size());
        for (uint32_t i = 0; i < nodes_split.Count(); ++i) {
            common::Split<> tmp_split(nodes_split[i], ':', nodes_split.SubLen(i));
            std::string pub_key = common::Encode::HexDecode(tmp_split[1]);
            auto account_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pub_key);
            auto country = ip::IpWithCountry::Instance()->GetCountryCode(tmp_split[0]);
            auto country_code = common::global_country_map[country];
            auto dht_key_mgr = dht::DhtKeyManager(
                    network::kVpnNetworkId,
                    country_code,
                    account_id);
            auto dht_key = dht_key_mgr.StrKey();
            ConfigNodeInfo conf_node{
                    country,
                    tmp_split[0],
                    pub_key,
                    dht_key
            };
            config_node_info_.push_back(conf_node);
            config_node_ips_.insert(tmp_split[0]);
            config_node_map_.insert(std::make_pair(account_id, conf_node));
        }
    }

    conf.Get("tenon", "vpn_count_svr", vpn_count_direct_info_);
    update_vpn_nodes_tick_.CutOff(
            kGetVpnNodesPeriod,
            std::bind(&UpdateVpnInit::GetVpnNodes, this));
    UpdateBlackNode();
    CheckSeverValid();
#endif
}

bool UpdateVpnInit::InitSuccess() {
    std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    return/* !vpn_nodes_map_.empty() && */!ver_buf_[valid_idx_].empty()/* && !route_nodes_map_.empty()*/;
}

void UpdateVpnInit::GetVpnSvrNodes(
        bool is_vip,
        const std::string& country,
        std::vector<VpnServerNodePtr>& nodes) {
    if (country.size() != 2) {
        std::lock_guard<std::mutex> gurad(ip_vpn_node_map_mutex_);
        auto iter = ip_vpn_node_map_.find(country);
        if (iter == ip_vpn_node_map_.end()) {
            return;
        }

        nodes.push_back(iter->second);
        return;
    }

    std::map<std::string, std::deque<VpnServerNodePtr>>* vpn_nodes_map = &vpn_nodes_map_;
    if (is_vip) {
        vpn_nodes_map = &vip_vpn_nodes_map_;
    }

	std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    auto iter = vpn_nodes_map->find(country);
    if (iter == vpn_nodes_map->end()) {
        return;
    }

    for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
        if (IsBlackIp((*qiter)->ip)) {
            continue;
        }

        (*qiter)->svr_port = common::GetVpnServerPort(
                common::Encode::HexDecode((*qiter)->dht_key),
                common::TimeUtils::TimestampDays(),
                (*qiter)->min_svr_port,
                (*qiter)->max_svr_port);
        nodes.push_back(*qiter);
	}
}

void UpdateVpnInit::GetRouteSvrNodes(
        bool is_vip,
        const std::string& country,
        std::vector<VpnServerNodePtr>& nodes) {
    std::map<std::string, std::deque<VpnServerNodePtr>>* route_nodes_map = &route_nodes_map_;
    if (is_vip) {
        route_nodes_map = &vip_route_nodes_map_;
    }

    std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
    auto iter = route_nodes_map->find(country);
    if (iter == route_nodes_map->end()) {
        return;
    }

    for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
        if (IsBlackIp((*qiter)->ip)) {
            continue;
        }

        (*qiter)->route_port = common::GetVpnRoutePort(
                common::Encode::HexDecode((*qiter)->dht_key),
                common::TimeUtils::TimestampDays(),
                (*qiter)->min_route_port,
                (*qiter)->max_route_port);
        nodes.push_back(*qiter);
    }
}

void UpdateVpnInit::GetVlanVpnNode(
        const std::string& country,
        std::vector<VpnServerNodePtr>& nodes) {
    std::lock_guard<std::mutex> guard(relay_nodes_map_mutex_);
    auto iter = relay_nodes_map_.find(country);
    if (iter == relay_nodes_map_.end()) {
        return;
    }

    for (auto siter = iter->second.begin(); siter != iter->second.end(); ++siter) {
        siter->second->svr_port = siter->second->min_udp_port;
        nodes.push_back(siter->second);
    }
}

void UpdateVpnInit::GetVlanRouteNode(
        const std::string& country,
        const std::string& key,
        std::vector<VpnServerNodePtr>& nodes) {
    std::lock_guard<std::mutex> guard(relay_nodes_map_mutex_);
    auto iter = relay_nodes_map_.find(country);
    if (iter == relay_nodes_map_.end()) {
        return;
    }
    auto siter = iter->second.find(key);
    for (auto node_iter = siter->second->relay_nodes.begin();
            node_iter != siter->second->relay_nodes.end(); ++node_iter) {
        (*node_iter)->route_port = common::GetVpnRoutePort(
                common::Encode::HexDecode((*node_iter)->dht_key),
                common::TimeUtils::TimestampDays(),
                (*node_iter)->min_route_port,
                (*node_iter)->max_route_port);
        nodes.push_back(*node_iter);
    }
}

struct TestInitNatNode {
    std::string ip;
    std::string pubkey;
    uint16_t min_port;
    uint16_t max_port;
};

void UpdateVpnInit::GetAccountInitBlocks(const std::string& account_id, std::string* res) {
#ifdef ENABLE_CLIENT_MODE
    transport::protobuf::Header message;
    auto local_dht = network::DhtManager::Instance()->GetDht(network::kVpnNetworkId);
    if (local_dht == nullptr) {
        return;
    }

    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(message, common::Encode::HexEncode(account_id));
    auto dht = network::UniversalManager::Instance()->GetUniversal(tenon::network::kUniversalNetworkId);
    if (dht == nullptr) {
        return;
    }

    message.set_hop_count(0);
    message.set_src_node_id(local_dht->local_node()->id());
    message.set_src_dht_key(local_dht->local_node()->dht_key());
    message.set_id(common::GlobalInfo::Instance()->MessageId());
    auto dht_key_mgr = dht::DhtKeyManager(
        common::GlobalInfo::Instance()->network_id(),
        0,
        account_id);
    message.set_des_dht_key(dht_key_mgr.StrKey());
    message.set_priority(transport::kTransportPriorityLow);
    message.set_type(common::kBlockMessage);
    block::protobuf::BlockMessage block_msg;
    auto attr_req = block_msg.mutable_account_init_req();
    attr_req->set_id(account_id);
    attr_req->set_count(16);
    message.set_data(block_msg.SerializeAsString());
    dht->SendToClosestNode(message);
    std::string key = db::kGlobalDbAccountInitBlocks + "_" + account_id;
    auto st = db::Db::Instance()->Get(key, res);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(message, common::Encode::HexEncode(account_id) + " load from db success.");
    if (st.ok() && !res->empty()) {
        return;
    }

    common::StateLock state_lock(1);
    auto callback = [&state_lock, res](int status, transport::protobuf::Header& header) {
        do  {
            if (status != transport::kTransportSuccess) {
                break;
            }

            if (header.type() != common::kBlockMessage) {
                break;
            }

            *res = header.data();
        } while (0);
        state_lock.Signal();
    };

    transport::SynchroWait::Instance()->Add(message.id(), 500 * 1000, callback, 1);
    state_lock.Wait();
#endif
}

std::string UpdateVpnInit::GetBftNodes() {
    std::string res;
    auto dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
    if (dht) {
        auto dht_nodes = *(dht->readonly_dht());
        for (auto iter = dht_nodes.begin(); iter != dht_nodes.end(); ++iter) {
            auto& tmp_node = *iter;
            auto net_id = dht::DhtKeyManager::DhtKeyGetNetId(tmp_node->dht_key());
            if (net_id == 4) {
                res += tmp_node->public_ip() + ":" + std::to_string(tmp_node->public_port) + ",";
            }
        }
    }

    return res;
}

void UpdateVpnInit::SetInitNodeInfo(
        const std::vector<init::VpnServerNodePtr>& node_vec,
        std::vector<int>& pos_vec,
        const std::string& country,
        bool is_vpn,
        bool is_vip,
        dht::protobuf::InitMessage& init_msg) {
    if (node_vec.empty()) {
        return;
    }

    if (pos_vec.size() > kMaxGetVpnNodesEachCountryNum) {
        std::random_shuffle(pos_vec.begin(), pos_vec.end());
    }

    for (uint32_t i = 0; i < pos_vec.size(); ++i) {
        if (i >= kMaxGetVpnNodesNum) {
            break;
        }

        if (node_vec[pos_vec[i]]->dht_key.size() != dht::kDhtKeySize &&
                node_vec[pos_vec[i]]->dht_key.size() != dht::kDhtKeySize * 2) {
            continue;
        }

        if (node_vec[pos_vec[i]]->pubkey.size() != security::kPublicKeySize &&
                node_vec[pos_vec[i]]->pubkey.size() != security::kPublicKeySize * 2) {
            continue;
        }

        dht::protobuf::VpnNodeInfo* new_node = nullptr;
        if (is_vip && is_vpn) {
            new_node = init_msg.add_vip_vpn_nodes();
//             if (country == "CN") {
                new_node->set_node_tag(common::kVpnVipNodeTag);
//             }
        } else if (!is_vip && is_vpn) {
            new_node = init_msg.add_vpn_nodes();
        } else if (is_vip && !is_vpn) {
            new_node = init_msg.add_vip_route_nodes();
            new_node->set_node_tag(common::kVpnVipNodeTag);
        } else if (!is_vip && !is_vpn) {
            new_node = init_msg.add_route_nodes();
        }

        new_node->set_country(country);
        new_node->set_ip(node_vec[pos_vec[i]]->ip);
        if (node_vec[pos_vec[i]]->dht_key.size() == dht::kDhtKeySize) {
            new_node->set_dhkey(node_vec[pos_vec[i]]->dht_key);
        } else if (node_vec[pos_vec[i]]->dht_key.size() == dht::kDhtKeySize * 2) {
            new_node->set_dhkey(common::Encode::HexDecode(node_vec[pos_vec[i]]->dht_key));
        }

        if (node_vec[pos_vec[i]]->pubkey.size() == security::kPublicKeySize) {
            new_node->set_pubkey(node_vec[pos_vec[i]]->pubkey);
        } else {
            new_node->set_pubkey(common::Encode::HexDecode(node_vec[pos_vec[i]]->pubkey));
        }

        new_node->set_min_route_port(node_vec[pos_vec[i]]->min_route_port);
        new_node->set_max_route_port(node_vec[pos_vec[i]]->max_route_port);
        new_node->set_min_svr_port(node_vec[pos_vec[i]]->min_svr_port);
        new_node->set_max_svr_port(node_vec[pos_vec[i]]->max_svr_port);
    }
}

void UpdateVpnInit::GetInitMessage(
        const std::string& account_id,
        dht::protobuf::InitMessage& init_msg,
        const std::string& uid,
        uint32_t trans_version) {
#ifdef ENABLE_CLIENT_MODE
    init_msg.set_bft_nodes(GetBftNodes());
    init_msg.set_version_info(ver_buf_[valid_idx_]);
    std::string block_init_res;
    GetAccountInitBlocks(account_id, &block_init_res);
    if (!block_init_res.empty()) {
        block::protobuf::BlockMessage block_msg;
        if (!block_msg.ParseFromString(block_init_res)) {
            auto account_init_res = block_msg.mutable_account_init_res();
            if (trans_version < transport::kTransportVersionNum) {
                account_init_res->set_balance(account_init_res->balance());
            }

            for (int32_t i = 0; i < account_init_res->tx_list_size(); ++i) {
                auto tx_item = account_init_res->mutable_tx_list(i);
                tx_item->set_amount(account_init_res->tx_list(i).amount());
            }

            block_init_res = block_msg.SerializeAsString();
        }

        init_msg.set_init_blocks(block_init_res);
    }

//     CreateVlanRleayNodes(init_msg);
    if (false && init_msg.use_conf_nodes()) {
        for (uint32_t i = 0; i < config_node_info_.size(); ++i) {
            auto node = init_msg.add_vpn_nodes();
            node->set_country(config_node_info_[i].country);
            node->set_ip(config_node_info_[i].ip);
            node->set_pubkey(config_node_info_[i].pk);
            node->set_dhkey(config_node_info_[i].dht_key);
        }
    } else {
        std::vector<init::VpnServerNodePtr> all_tmp_vec;
        std::vector<int> all_pos_vec;
        int all_idx = 0;
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        for (auto iter = vpn_nodes_map_.begin(); iter != vpn_nodes_map_.end(); ++iter) {
            std::vector<init::VpnServerNodePtr> tmp_vec;
            std::vector<int> pos_vec;
            int idx = 0;
            std::deque<VpnServerNodePtr> tmp_queue = iter->second;
            while (!tmp_queue.empty()) {
                auto node = tmp_queue.front();
                tmp_queue.pop_front();
                if (IsBlackIp(node->ip)/* && iter->first != "CN"*/) {
                    continue;
                }

                if (IsInvalidNode(node->acccount_id, false) || common::IsVlanIp(node->ip)) {
                    continue;
                }

                uint32_t node_weight = 1;
                for (uint32_t i = 0; i < node_weight; ++i) {
                    tmp_vec.push_back(node);
                    pos_vec.push_back(idx++);
                    if (iter->first != "CN") {
                        all_tmp_vec.push_back(node);
                        all_pos_vec.push_back(all_idx++);
                    }
                }
            }

            SetInitNodeInfo(tmp_vec, pos_vec, iter->first, true, false, init_msg);
            if (iter->first == "CN") {
                SetInitNodeInfo(tmp_vec, pos_vec, iter->first, true, true, init_msg);
            }
        }

        SetInitNodeInfo(all_tmp_vec, all_pos_vec, "AA", true, false, init_msg);
    }

    {
        std::vector<init::VpnServerNodePtr> all_tmp_vec;
        std::vector<int> all_pos_vec;
        int all_idx = 0;
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        for (auto iter = vip_vpn_nodes_map_.begin(); iter != vip_vpn_nodes_map_.end(); ++iter) {
            std::vector<init::VpnServerNodePtr> tmp_vec;
            std::vector<int> pos_vec;
            int idx = 0;
            std::deque<VpnServerNodePtr> tmp_queue = iter->second;
            while (!tmp_queue.empty()) {
                auto node = tmp_queue.front();
                tmp_queue.pop_front();
                if (IsBlackIp(node->ip)/* && iter->first != "CN"*/) {
                    continue;
                }

                if (IsInvalidNode(node->acccount_id, false) || common::IsVlanIp(node->ip)) {
                    continue;
                }

                uint32_t node_weight = 1;
                for (uint32_t i = 0; i < node_weight; ++i) {
                    tmp_vec.push_back(node);
                    pos_vec.push_back(idx++);
                    if (iter->first != "CN") {
                        all_tmp_vec.push_back(node);
                        all_pos_vec.push_back(all_idx++);
                    }
                }
            }

//             if (iter->first == "US") {
//                 continue;
//             }
// 
            SetInitNodeInfo(tmp_vec, pos_vec, iter->first, true, true, init_msg);
        }

//         SetInitNodeInfo(all_tmp_vec, all_pos_vec, "US", true, true, init_msg);
    }

    {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        for (auto iter = route_nodes_map_.begin(); iter != route_nodes_map_.end(); ++iter) {
            std::vector<init::VpnServerNodePtr> tmp_vec;
            std::vector<int> pos_vec;
            int idx = 0;
            std::deque<VpnServerNodePtr> tmp_queue = iter->second;
            while (!tmp_queue.empty()) {
                auto node = tmp_queue.front();
                tmp_queue.pop_front();
                if (IsBlackIp(node->ip)) {
                    continue;
                }

                if (IsInvalidNode(node->acccount_id, false) || common::IsVlanIp(node->ip)) {
                    continue;
                }

                if (iter->first == "CN" && (
                    node->min_route_port == common::kVpnRoutePortRangeMin ||
                    node->min_route_port == 0 ||
                    node->max_route_port == common::kVpnRoutePortRangeMax ||
                    node->max_route_port == 0)) {
                    continue;
                }

                uint32_t node_weight = 1;
                for (uint32_t i = 0; i < node_weight; ++i) {
                    tmp_vec.push_back(node);
                    pos_vec.push_back(idx++);
                }
            }

            SetInitNodeInfo(tmp_vec, pos_vec, iter->first, false, false, init_msg);
        }
    }

    {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        for (auto iter = vip_route_nodes_map_.begin(); iter != vip_route_nodes_map_.end(); ++iter) {
            std::vector<init::VpnServerNodePtr> tmp_vec;
            std::vector<int> pos_vec;
            int idx = 0;
            std::deque<VpnServerNodePtr> tmp_queue = iter->second;
            while (!tmp_queue.empty()) {
                auto node = tmp_queue.front();
                tmp_queue.pop_front();
                if (IsBlackIp(node->ip)) {
                    continue;
                }

                if (IsInvalidNode(node->acccount_id, false) || common::IsVlanIp(node->ip)) {
                    continue;
                }

                if (iter->first == "CN" && (
                    node->min_route_port == common::kVpnRoutePortRangeMin ||
                    node->min_route_port == 0 ||
                    node->max_route_port == common::kVpnRoutePortRangeMax ||
                    node->max_route_port == 0)) {
                    continue;
                }

                uint32_t node_weight = 1;
                for (uint32_t i = 0; i < node_weight; ++i) {
                    tmp_vec.push_back(node);
                    pos_vec.push_back(idx++);
                }
            }

            SetInitNodeInfo(tmp_vec, pos_vec, iter->first, false, true, init_msg);
        }
    }

    {
        auto iter = route_nodes_map_.find("USD");
        if (iter != route_nodes_map_.end()) {
            std::vector<init::VpnServerNodePtr> tmp_vec;
            std::vector<int> pos_vec;
            int idx = 0;
            std::deque<VpnServerNodePtr> tmp_queue = iter->second;
            while (!tmp_queue.empty()) {
                auto node = tmp_queue.front();
                tmp_queue.pop_front();
                if (IsBlackIp(node->ip)) {
                    continue;
                }

                if (IsInvalidNode(node->acccount_id, false) || common::IsVlanIp(node->ip)) {
                    continue;
                }

                uint32_t node_weight = 1;
                for (uint32_t i = 0; i < node_weight; ++i) {
                    tmp_vec.push_back(node);
                    pos_vec.push_back(idx++);
                }
            }

            SetInitNodeInfo(tmp_vec, pos_vec, "CN", false, false, init_msg);
        }
    }
#endif
}

void UpdateVpnInit::CreateVlanRleayNodes(dht::protobuf::InitMessage& init_msg) {
#ifdef ENABLE_CLIENT_MODE
    std::vector<dht::NodePtr> tmp_nodes;
    auto dht = network::DhtManager::Instance()->GetDht(network::kVpnRouteNetworkId);
    if (dht == nullptr) {
        return;
    }

    auto local_nodes = *(dht->readonly_dht());  // change must copy
    local_nodes.push_back(dht->local_node());

    auto new_node = init_msg.add_route_nodes();
    new_node->set_country(common::global_code_to_country_map[common::GlobalInfo::Instance()->country()]);
    new_node->set_ip(dht->local_node()->public_ip());
    new_node->set_min_route_port(common::GlobalInfo::Instance()->min_route_port());
    new_node->set_max_route_port(common::GlobalInfo::Instance()->max_route_port());
    new_node->set_min_udp_port(common::GlobalInfo::Instance()->min_udp_port());
    new_node->set_max_udp_port(common::GlobalInfo::Instance()->max_udp_port());
    new_node->set_pubkey(security::Schnorr::Instance()->str_pubkey());
    new_node->set_node_tag(common::GlobalInfo::Instance()->node_tag());
    if (dht->local_node()->dht_key().size() == dht::kDhtKeySize) {
        new_node->set_dhkey(dht->local_node()->dht_key());
    } else if (dht->local_node()->dht_key().size() == dht::kDhtKeySize * 2) {
        new_node->set_dhkey(common::Encode::HexDecode(dht->local_node()->dht_key()));
    }
#endif
}

void UpdateVpnInit::SetVersionInfo(const std::string& ver) {
    INIT_ERROR("set version info: %s", ver.c_str());
    uint32_t idle_idx = (valid_idx_ + 1) % 2;
    ver_buf_[idle_idx] = ver;
    valid_idx_ = idle_idx;
    common::Split<> splits(ver.c_str(), ',', ver.size());
    for (uint32_t split_idx = 0; split_idx < splits.Count(); ++split_idx) {
        common::Split<> tmp_split(splits[split_idx], ';', splits.SubLen(split_idx));
        if (tmp_split.Count() >= 2) {
            if (memcmp(tmp_split[0], "free_max_bw", strlen("free_max_bw")) == 0) {
                common::StringUtil::ToUint64(tmp_split[1], (uint64_t*)&max_free_bandwidth_);
            }

            if (memcmp(tmp_split[0], "vip_max_bw", strlen("vip_max_bw")) == 0) {
                common::StringUtil::ToUint64(tmp_split[1], (uint64_t*)&max_vip_bandwidth_);
            }

            if (memcmp(tmp_split[0], "vpn_country", strlen("vpn_country")) == 0) {
                common::Split<> country_split(tmp_split[1], '1', tmp_split.SubLen(1));
                std::lock_guard<std::mutex> guard(country_vec_mutex_);
                country_vec_.clear();
                for (uint32_t cnt_idx = 0; cnt_idx < country_split.Count(); ++cnt_idx) {
                    if (country_split.SubLen(cnt_idx) == 2) {
                        country_vec_.push_back(country_split[cnt_idx]);
                    }
                }
            }
        }
    }
}

void UpdateVpnInit::GetVpnNodes() {
    std::vector<std::string> country_vec;
    {
        std::lock_guard<std::mutex> guard(country_vec_mutex_);
        country_vec = country_vec_;
    }

    GetNetworkNodes(country_vec, network::kVpnNetworkId);
    GetNetworkNodes(country_vec, network::kVpnRouteNetworkId);
    update_vpn_nodes_tick_.CutOff(
            kGetVpnNodesPeriod,
            std::bind(&UpdateVpnInit::GetVpnNodes, this));
}

void UpdateVpnInit::GetNetworkNodes(
        const std::vector<std::string>& country_vec,
        uint32_t network_id) {
#ifndef MAKE_CLIENT_LIB
    for (uint32_t i = 0; i < country_vec.size(); ++i) {
        auto country = country_vec[i];
        auto uni_dht = std::dynamic_pointer_cast<network::Universal>(
                network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId));
        if (!uni_dht) {
            continue;
        }

        auto dht_nodes = uni_dht->LocalGetNetworkNodes(
                (uint32_t)network_id,
                (uint8_t)common::global_country_map[country],
                (uint32_t)128);
        if (dht_nodes.empty()) {
            dht_nodes = uni_dht->RemoteGetNetworkNodes(
                (uint32_t)network_id,
                (uint8_t)common::global_country_map[country],
                (uint32_t)4);
        }

        INIT_ERROR("GetNetworkNodes network_id: %d, count: %u", network_id, dht_nodes.size());
        if (dht_nodes.empty()) {
            continue;
        }

        for (auto iter = dht_nodes.begin(); iter != dht_nodes.end(); ++iter) {
            auto& tmp_node = *iter;
            if (IsBlackIp(tmp_node->public_ip())) {
//                 if (!(network_id == network::kVpnNetworkId && country == "CN")) {
                    continue;
//                 }
            }

            if (common::IsVlanIp(tmp_node->public_ip())) {
                continue;
            }

            auto country = ip::IpWithCountry::Instance()->GetCountryCode(tmp_node->public_ip());
            auto country_code = common::global_country_map[country];
            if (network_id == network::kVpnNetworkId) {
                auto dht_key_mgr = dht::DhtKeyManager(
                    network::kVpnNetworkId,
                    country_code,
                    tmp_node->id());
                auto dht_key = dht_key_mgr.StrKey();
                auto iter = joined_vpn_map_.find(tmp_node->id());
                if (iter == joined_vpn_map_.end()) {
                    ConfigNodeInfo conf_node{
                        country,
                        tmp_node->public_ip(),
                        tmp_node->pubkey_str(),
                        dht_key
                    };
                    uint16_t svr_port = common::GetVpnServerPort(
                        dht_key,
                        common::TimeUtils::TimestampDays(),
                        tmp_node->min_svr_port,
                        tmp_node->max_svr_port);
                    bool isReachable = false;
//                     common::RemoteReachable(tmp_node->public_ip(), svr_port, &isReachable);
                    if (!isReachable) {
                        INIT_ERROR("join new vpn node can't reachable [%s:%d], id[%s], dht_key[%s], min_port: %d, max_port: %d, port: %d, day tm[%u]",
                            tmp_node->public_ip().c_str(),
                            svr_port,
                            common::Encode::HexEncode(tmp_node->id()).c_str(),
                            common::Encode::HexEncode(dht_key).c_str(),
                            tmp_node->min_svr_port,
                            tmp_node->max_svr_port,
                            svr_port,
                            common::TimeUtils::TimestampDays());
                        continue;
                    }

                    joined_vpn_map_[tmp_node->id()] = conf_node;
                }
                
                auto citer = config_node_map_.find(tmp_node->id());
                if (citer != config_node_map_.end()) {
                    if (dht_key != tmp_node->dht_key()) {
                        INIT_ERROR("get init vpn node failed![%s], id[%s], dht_key:[%s:%s]",
                            tmp_node->public_ip().c_str(),
                            common::Encode::HexEncode(tmp_node->id()).c_str(),
                            common::Encode::HexEncode(dht_key).c_str(),
                            common::Encode::HexEncode(tmp_node->dht_key()).c_str());
                        tmp_node->set_dht_key(dht_key);
                        continue;
                    }
                }
            } else {
                auto dht_key_mgr = dht::DhtKeyManager(
                    network::kVpnRouteNetworkId,
                    country_code,
                    tmp_node->id());
                auto dht_key = dht_key_mgr.StrKey();

                auto iter = joined_route_map_.find(tmp_node->id());
                if (iter == joined_route_map_.end()) {
                    ConfigNodeInfo conf_node{
                        country,
                        tmp_node->public_ip(),
                        tmp_node->pubkey_str(),
                        dht_key
                    };
                    uint16_t route_port = common::GetVpnRoutePort(
                        dht_key,
                        common::TimeUtils::TimestampDays(),
                        tmp_node->min_route_port,
                        tmp_node->max_route_port);
                    bool isReachable = false;
//                     common::RemoteReachable(tmp_node->public_ip(), route_port, &isReachable);
                    if (!isReachable) {
                        INIT_ERROR("join new route node can't reachable [%s:%d], id[%s], dht_key[%s], min_port: %d, max_port: %d, port: %d, day tm[%u]",
                            tmp_node->public_ip().c_str(),
                            route_port,
                            common::Encode::HexEncode(tmp_node->id()).c_str(),
                            common::Encode::HexEncode(dht_key).c_str(),
                            tmp_node->min_route_port,
                            tmp_node->max_route_port,
                            route_port,
                            common::TimeUtils::TimestampDays());
                        continue;
                    }
                    joined_route_map_[tmp_node->id()] = conf_node;
                }
            }
            auto node_ptr = std::make_shared<VpnServerNode>(
                    tmp_node->public_ip(),
                    tmp_node->min_svr_port,
                    tmp_node->max_svr_port,
                    tmp_node->min_route_port,
                    tmp_node->max_route_port,
                    tmp_node->min_udp_port,
                    tmp_node->max_udp_port,
                    tmp_node->node_weight,
                    "",
                    common::Encode::HexEncode(tmp_node->dht_key()),
                    common::Encode::HexEncode(tmp_node->pubkey_str()),
                    "",
                    true,
                    tmp_node->node_tag());
            uint32_t node_netid = dht::DhtKeyManager::DhtKeyGetNetId(tmp_node->dht_key());
            if (node_netid == network::kVpnNetworkId) {
                if (country == "CN") {
                    INIT_ERROR("add new node country: %s, ip: %s, min: %d, max: %d",
                        country.c_str(),
                        node_ptr->ip.c_str(),
                        node_ptr->min_svr_port,
                        node_ptr->max_svr_port);
                }
                AddToVpnMap(country, node_ptr);
            }

            if (node_netid == network::kVpnRouteNetworkId) {
                AddToRouteMap(country, node_ptr);
            }
        }
    }
#endif
}

void UpdateVpnInit::UpdateAccountBlockInfo(const std::string& block_str) {
#ifdef ENABLE_CLIENT_MODE
    block::protobuf::BlockMessage init_blocks;
#else
    client::protobuf::BlockMessage init_blocks;
#endif
    if (init_blocks.ParseFromString(block_str)) {
        if (init_blocks.has_account_init_res()) {
            if (init_balance_ == -1) {
                init_balance_ = init_blocks.account_init_res().balance();
            }

            for (int32_t i = 0; i < init_blocks.account_init_res().block_list_size(); ++i) {
                for (int32_t tx_idx = 0; tx_idx < init_blocks.account_init_res().block_list(i).tx_list_size(); ++tx_idx) {
                    auto& tx_info = init_blocks.account_init_res().block_list(i).tx_list(tx_idx);
                    if (tx_info.from() != common::GlobalInfo::Instance()->id() &&
                            tx_info.to() != common::GlobalInfo::Instance()->id()) {
                        continue;
                    }

                    if (tx_info.type() == common::kConsensusPayForCommonVpn &&
                        tx_info.status() != 0) {
                        continue;
                    }

                    if (tx_info.height() >= max_height_ ||
                        max_height_ == common::kInvalidUint64) {
                        max_height_ = init_blocks.account_init_res().block_list(i).height();
                        init_balance_ = init_blocks.account_init_res().balance();
                    }

                    if (tx_info.type() == common::kConsensusPayForCommonVpn &&
                        tx_info.height() >= max_pay_for_vpn_height_) {
                        max_pay_for_vpn_tm_ = init_blocks.account_init_res().block_list(i).timestamp();
                        max_pay_for_vpn_amount_ = tx_info.amount();
                        max_pay_for_vpn_height_ = tx_info.height();
                    }
                    std::cout << "get block item: " << common::Encode::HexEncode(tx_info.from()) << ", " << common::Encode::HexEncode(tx_info.to())
                        << ", " << tx_info.balance() << ", " << tx_info.amount() << std::endl;
                    auto tx_info_ptr = std::make_shared<TxinfoItem>({
                        tx_info,
                        init_blocks.account_init_res().block_list(i).timestamp(),
                        init_blocks.account_init_res().block_list(i).height() });
                    std::lock_guard<std::mutex> guard(init_blocks_mutex_);
                    init_blocks_.push(tx_info_ptr);
                }
            }
        }
    }
}

void UpdateVpnInit::HandleBftNodes(const std::string& nodes) {
    common::Split<> nodes_split(nodes.c_str(), ',', nodes.size());
    for (uint32_t i = 0; i < nodes_split.Count(); ++i) {
        common::Split<> item_split(nodes_split[i], ':', nodes_split.SubLen(i));
        if (item_split.Count() != 2) {
            continue;
        }

        std::lock_guard<std::mutex> guard(bft_nodes_mutex_);
        std::string ip(item_split[0], item_split.SubLen(0));
        if (bft_nodes_.find(
                std::string(item_split[0], item_split.SubLen(0))) != bft_nodes_.end()) {
            continue;
        }

        bft_nodes_.insert(ip);
        uint16_t port = 0;
        if (!common::StringUtil::ToUint16(
                std::string(item_split[1], item_split.SubLen(1)),
                &port)) {
            continue;
        }
        bft_nodes_vec_.push_back(std::make_pair(ip, port));
    }
}

// for client
void UpdateVpnInit::BootstrapInit(const dht::protobuf::InitMessage& init_info) {
    HandleBftNodes(init_info.bft_nodes());
    SetVersionInfo(init_info.version_info());
    if (init_info.has_vpn_node_count()) {
        std::lock_guard<std::mutex> guard(init_vpn_count_info_mutex_);
        if (init_vpn_count_info_.size() < init_info.vpn_node_count().size()) {
            init_vpn_count_info_ = init_info.vpn_node_count();
        }

        if (init_info.has_vpn_count_svr() && init_info.vpn_count_svr().size() > 0) {
            local_vpn_count_direct_info_ = init_info.vpn_count_svr();
        }
    }

    if (init_info.has_init_blocks() && common::GlobalInfo::Instance()->is_client()) {
        UpdateAccountBlockInfo(init_info.init_blocks());
    }

    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (!uni_dht) {
        NETWORK_ERROR("get uni dht failed!");
        return;
    }

    if (!uni_dht->local_node()->client_mode && !common::GlobalInfo::Instance()->is_vlan_node()) {
        return;
    }

    for (int32_t i = 0; i < init_info.vpn_nodes_size(); ++i) {
        if (IsBlackIp(init_info.vpn_nodes(i).ip()) || common::IsVlanIp(init_info.vpn_nodes(i).ip())) {
            continue;
        }

        HandleNodes(false, init_info.vpn_nodes(i));
    }

    for (int32_t i = 0; i < init_info.route_nodes_size(); ++i) {
        if (IsBlackIp(init_info.route_nodes(i).ip()) ||
                common::IsVlanIp(init_info.route_nodes(i).ip())) {
            continue;
        }

        HandleNodes(true, init_info.route_nodes(i));
    }

    for (int32_t i = 0; i < init_info.vip_vpn_nodes_size(); ++i) {
        if (IsBlackIp(init_info.vip_vpn_nodes(i).ip()) ||
                common::IsVlanIp(init_info.vip_vpn_nodes(i).ip())) {
            continue;
        }

        HandleNodes(false, init_info.vip_vpn_nodes(i));
    }

    for (int32_t i = 0; i < init_info.vip_route_nodes_size(); ++i) {
        if (IsBlackIp(init_info.vip_route_nodes(i).ip()) ||
                common::IsVlanIp(init_info.vip_route_nodes(i).ip())) {
            continue;
        }

        HandleNodes(true, init_info.vip_route_nodes(i));
    }

    {
        if (init_info_.empty()) {
            std::lock_guard<std::mutex> guard(init_info_mutex_);
            if (init_info_.empty() ||
                    init_info.vpn_nodes_size() > static_cast<int>(init_info_node_count_)) {
                init_info_node_count_ = init_info.vpn_nodes_size();
                init_info_ = common::Encode::HexEncode(init_info.SerializeAsString());
            }
        }
    }
}

void UpdateVpnInit::GetInitInfo(std::string* init_info) {
    std::lock_guard<std::mutex> guard(init_info_mutex_);
    *init_info = init_info_;
}

void UpdateVpnInit::HandleRelayNodes(
        const std::string& country,
        const dht::protobuf::VpnNodeInfo& vpn_node,
        VpnServerNodePtr& route_node_ptr) {
    for (int i = 0; i < vpn_node.relay_vpn_nodes_size(); ++i) {
        auto node_info = vpn_node.relay_vpn_nodes(i);
        security::PublicKey pubkey;
        if (pubkey.Deserialize(node_info.pubkey()) != 0) {
            return;
        }

        std::string sec_key;
        auto res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key);
        if (res != security::kSecuritySuccess) {
            INIT_ERROR("create sec key failed!");
            return;
        }

        auto node_ptr = std::make_shared<VpnServerNode>(
                node_info.ip(),
                0,
                0,
                0,
                0,
                node_info.min_udp_port(),
                0,
                1,
                common::Encode::HexEncode(sec_key),
                "",
                common::Encode::HexEncode(node_info.pubkey()),
                common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPublicKey(node_info.pubkey())),
                true,
                vpn_node.node_tag());
        std::string key = node_info.ip() + "_" + std::to_string(node_info.min_udp_port());
        std::lock_guard<std::mutex> guard(relay_nodes_map_mutex_);
        auto iter = relay_nodes_map_.find(country);
        if (iter != relay_nodes_map_.end()) {
            auto siter = iter->second.find(key);
            if (siter != iter->second.end()) {
                siter->second->relay_nodes.push_back(route_node_ptr);
                if (siter->second->relay_nodes.size() >= kMaxRelayCount) {
                    siter->second->relay_nodes.pop_front();
                }
            } else {
                node_ptr->relay_nodes.push_back(route_node_ptr);
                iter->second[key] = node_ptr;
            }
        } else {
            node_ptr->relay_nodes.push_back(route_node_ptr);
            std::unordered_map<std::string, VpnServerNodePtr> tmp_map;
            tmp_map[key] = node_ptr;
            relay_nodes_map_[country] = tmp_map;
        }
    }
}

std::string UpdateVpnInit::GetAllNodes(bool is_vip) {
    std::string vpn_nodes;
    std::string route_nodes;
    {
        std::map<std::string, std::deque<VpnServerNodePtr>>* vpn_map = &vpn_nodes_map_;
        if (is_vip && vip_vpn_nodes_map_.size() > 3) {
            vpn_map = &vip_vpn_nodes_map_;
        }

        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        for (auto iter = vpn_map->begin(); iter != vpn_map->end(); ++iter) {
            std::string item = iter->first + ";";
            for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
                uint16_t vpn_port = common::GetVpnServerPort(
                        common::Encode::HexDecode((*qiter)->dht_key),
                        common::TimeUtils::TimestampDays(),
                        (*qiter)->min_svr_port,
                        (*qiter)->max_svr_port);
                item += (*qiter)->ip + ":" + std::to_string(vpn_port) + ":0:" +
                        (*qiter)->seckey + ":" + (*qiter)->pubkey + ":" + (*qiter)->dht_key + ":,";
            }

            vpn_nodes += item + "`";
        }
    }

    {
        std::map<std::string, std::deque<VpnServerNodePtr>>* route_map = &route_nodes_map_;
        if (is_vip && vip_route_nodes_map_.size() > 3) {
            route_map = &vip_route_nodes_map_;
        }

        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        for (auto iter = route_map->begin(); iter != route_map->end(); ++iter) {
            std::string item = iter->first + ";";
            for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
                uint16_t route_port = common::GetVpnRoutePort(
                        common::Encode::HexDecode((*qiter)->dht_key),
                        common::TimeUtils::TimestampDays(),
                        (*qiter)->min_route_port,
                        (*qiter)->max_route_port);
                item += (*qiter)->ip + ":0:" + std::to_string(route_port) + ":" +
                        (*qiter)->seckey + ":" + (*qiter)->pubkey + ":" + (*qiter)->dht_key + ":,";
            }

            route_nodes += item + "`";
        }
    }

    return vpn_nodes + "~" + route_nodes;
}

void UpdateVpnInit::AddToVpnMap(const std::string& country, VpnServerNodePtr& node_ptr) {
    std::map<std::string, std::deque<VpnServerNodePtr>>* vpn_nodes_map = &vpn_nodes_map_;
    if (node_ptr->node_tag == common::kVpnVipNodeTag) {
        vpn_nodes_map = &vip_vpn_nodes_map_;
    }
    
    std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    vpn_dht_key_node_map_[common::Encode::HexDecode(node_ptr->dht_key)] = node_ptr;
    auto sub_iter = vpn_nodes_map->find(country);
    if (sub_iter != vpn_nodes_map->end()) {
        auto e_iter = std::find_if(
                sub_iter->second.begin(),
                sub_iter->second.end(),
                [node_ptr](const VpnServerNodePtr& ptr) {
            return node_ptr->dht_key == ptr->dht_key;
        });
        if (e_iter == sub_iter->second.end()) {
            sub_iter->second.push_back(node_ptr);
            if (sub_iter->second.size() > 128) {
                sub_iter->second.pop_front();
            }
        }
    } else {
        std::deque<VpnServerNodePtr> tmp_queue;
        tmp_queue.push_back(node_ptr);
        (*vpn_nodes_map)[country] = tmp_queue;
    }
}

void UpdateVpnInit::AddToRouteMap(const std::string& country, VpnServerNodePtr& node_ptr) {
    std::map<std::string, std::deque<VpnServerNodePtr>>* route_nodes_map = &route_nodes_map_;
    if (node_ptr->node_tag == common::kVpnVipNodeTag) {
        route_nodes_map = &vip_route_nodes_map_;
    }

    std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
    route_dht_key_node_map_[common::Encode::HexDecode(node_ptr->dht_key)] = node_ptr;
    auto sub_iter = route_nodes_map->find(country);
    if (sub_iter != route_nodes_map->end()) {
        auto e_iter = std::find_if(
                sub_iter->second.begin(),
                sub_iter->second.end(),
                [node_ptr](const VpnServerNodePtr& ptr) {
            return node_ptr->dht_key == ptr->dht_key;
        });
        if (e_iter == sub_iter->second.end()) {
            sub_iter->second.push_back(node_ptr);
            if (sub_iter->second.size() > 128) {
                sub_iter->second.pop_front();
            }
        }
    } else {
        std::deque<VpnServerNodePtr> tmp_queue;
        tmp_queue.push_back(node_ptr);
        (*route_nodes_map)[country] = tmp_queue;
    }
}

int UpdateVpnInit::GetPortRangeByDhtKey(
        const std::string& dht_key,
        bool is_route,
        uint16_t* min_port,
        uint16_t* max_port) {
    if (is_route) {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        auto iter = route_dht_key_node_map_.find(dht_key);
        if (iter != route_dht_key_node_map_.end()) {
            *min_port = iter->second->min_route_port;
            *max_port = iter->second->max_route_port;
        }
    } else {
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        auto iter = vpn_dht_key_node_map_.find(dht_key);
        if (iter != vpn_dht_key_node_map_.end()) {
            *min_port = iter->second->min_svr_port;
            *max_port = iter->second->max_svr_port;
        }
    }

    return 0;
}

void UpdateVpnInit::HandleNodes(bool is_route, const dht::protobuf::VpnNodeInfo& vpn_node) {
    // ecdh encrypt vpn password
    security::PublicKey pubkey;
    if (pubkey.Deserialize(vpn_node.pubkey()) != 0) {
        return;
    }

    std::string sec_key;
    auto res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key);
    if (res != security::kSecuritySuccess) {
        INIT_ERROR("create sec key failed!");
        return;
    }

    std::string dht_key = vpn_node.dhkey();
    std::string node_country = vpn_node.country();
    auto account_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vpn_node.pubkey());
    auto node_ptr = std::make_shared<VpnServerNode>(
            vpn_node.ip(),
            vpn_node.min_svr_port(),
            vpn_node.max_svr_port(),
            vpn_node.min_route_port(),
            vpn_node.max_route_port(),
            vpn_node.min_udp_port(),
            vpn_node.max_udp_port(),
            vpn_node.node_weight(),
            common::Encode::HexEncode(sec_key),
            common::Encode::HexEncode(dht_key),
            common::Encode::HexEncode(vpn_node.pubkey()),
            common::Encode::HexEncode(account_id),
            true,
            vpn_node.node_tag());
    if (is_route &&
            vpn_node.relay_vpn_nodes_size() > 0) {
        HandleRelayNodes(node_country, vpn_node, node_ptr);
    }

    if (!is_route) {
        std::lock_guard<std::mutex> gurad(ip_vpn_node_map_mutex_);
        ip_vpn_node_map_[vpn_node.ip()] = node_ptr;
    }

    AddNode(vpn_node.dhkey(), node_ptr);
    if (!is_route) {
        AddToVpnMap(node_country, node_ptr);
    } else {
        AddToRouteMap(node_country, node_ptr);
    }
}

void UpdateVpnInit::UpdateBlackNode() {
    FILE* fp = fopen("./conf/black", "r");
    if (fp != nullptr) {
        char buf[102400];
        std::set<std::string> black_set;
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            common::Split<10240> spliter(buf, ',');
            for (uint32_t i = 0; i < spliter.Count(); ++i) {
                if (spliter.SubLen(i) > 7) {
                    black_set.insert(spliter[i]);
                }
            }
        }
        fclose(fp);

        std::lock_guard<std::mutex> guard(block_node_set_mutex_);
        block_node_set_ = black_set;
    }

    update_black_nodes_tick_.CutOff(
            kUpdateBlackNodesPeriod,
            std::bind(&UpdateVpnInit::UpdateBlackNode, this));
}

bool UpdateVpnInit::IsBlackIp(const std::string& ip) {
    std::lock_guard<std::mutex> guard(block_node_set_mutex_);
    return (block_node_set_.find(ip) != block_node_set_.end());
}

bool UpdateVpnInit::IsInvalidNode(const std::string& id, bool route) {
    if (route) {
        std::lock_guard<std::mutex> guard(invalid_route_set_mutex_);
        return invalid_route_set_.find(id) != invalid_route_set_.end();
    }

    std::lock_guard<std::mutex> guard(invalid_server_set_mutex_);
    return invalid_server_set_.find(id) != invalid_server_set_.end();
}


void UpdateVpnInit::CheckSeverValid() {
    std::map<std::string, std::deque<VpnServerNodePtr>> vpn_nodes_map;
    {
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        vpn_nodes_map = vpn_nodes_map_;
    }

    for (auto iter = vpn_nodes_map.begin(); iter != vpn_nodes_map.end(); ++iter) {
        for (auto sub_iter = iter->second.begin(); sub_iter != iter->second.end(); ++sub_iter) {
            auto node_ptr = *sub_iter;
            uint16_t port = common::GetVpnServerPort(
                    common::Encode::HexDecode(node_ptr->dht_key),
                    common::TimeUtils::TimestampDays(),
                    node_ptr->min_svr_port,
                    node_ptr->max_svr_port);
            int i = 0;
            for (; i < 3; ++i) {
                bool reacheable = false;
//                 common::RemoteReachable(node_ptr->ip, port, &reacheable);
                if (reacheable) {
                    break;
                }
            }

            {
                std::lock_guard<std::mutex> guard(invalid_server_set_mutex_);
                if (i == 3) {
                    invalid_server_set_.insert(node_ptr->acccount_id);
                    INIT_ERROR("check server invalid node [dht_key: %s] [ip: %s][port: %d][min: %d][max: %d]",
                        node_ptr->dht_key.c_str(),
                        node_ptr->ip.c_str(),
                        port,
                        node_ptr->min_svr_port,
                        node_ptr->max_svr_port);
                } else {
                    invalid_server_set_.erase(node_ptr->acccount_id);
                }
            }
        }
    }

    std::map<std::string, std::deque<VpnServerNodePtr>> route_nodes_map;
    {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        route_nodes_map = route_nodes_map_;
    }

    for (auto iter = route_nodes_map.begin(); iter != route_nodes_map.end(); ++iter) {
        for (auto sub_iter = iter->second.begin(); sub_iter != iter->second.end(); ++sub_iter) {
            auto node_ptr = *sub_iter;
            uint16_t port = common::GetVpnRoutePort(
                    common::Encode::HexDecode(node_ptr->dht_key),
                    common::TimeUtils::TimestampDays(),
                    node_ptr->min_route_port,
                    node_ptr->max_route_port);
            int i = 0;
            for (; i < 3; ++i) {
                bool reacheable = false;
//                 common::RemoteReachable(node_ptr->ip, port, &reacheable);
                if (reacheable) {
                    break;
                }
            }

            {
                std::lock_guard<std::mutex> guard(invalid_route_set_mutex_);
                if (i == 3) {
                    invalid_route_set_.insert(node_ptr->acccount_id);
                    INIT_ERROR("check route invalid node[%s][ip: %s][port: %d][min: %d][max: %d]",
                            node_ptr->dht_key.c_str(), node_ptr->ip.c_str(), port,
                            node_ptr->min_route_port, node_ptr->max_route_port);
                } else {
                    invalid_route_set_.erase(node_ptr->acccount_id);
                }
            }
        }
    }

    check_valid_nodes_tick_.CutOff(
            kUpdateBlackNodesPeriod,
            std::bind(&UpdateVpnInit::CheckSeverValid, this));
}

void UpdateVpnInit::AddNode(const std::string& dht_key, VpnServerNodePtr& node) {
    std::lock_guard<std::mutex> guard(all_nodes_map_mutex_);
    all_nodes_map_[dht_key] = node;
}

void UpdateVpnInit::UpdateNodePorts(
        const std::string& dht_key,
        uint16_t min_r_port,
        uint16_t max_r_port,
        uint16_t min_s_port,
        uint16_t max_s_port) {
    std::lock_guard<std::mutex> guard(all_nodes_map_mutex_);
    auto iter = all_nodes_map_.find(dht_key);
    if (iter != all_nodes_map_.end()) {
        iter->second->min_route_port = min_r_port;
        iter->second->max_route_port = max_r_port;
        iter->second->min_svr_port = min_s_port;
        iter->second->max_svr_port = max_s_port;
    }
}

}  // namespace init

}  // namespace tenon
