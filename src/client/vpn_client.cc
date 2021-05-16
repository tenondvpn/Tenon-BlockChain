#include "stdafx.h"
#include "client/client_universal_dht.h"
#include "client/vpn_client.h"

#include <cassert>

#include "common/log.h"
#include "common/utils.h"
#include "common/config.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "common/state_lock.h"
#include "common/split.h"
#include "common/tick.h"
#include "common/string_utils.h"
#include "common/time_utils.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/schnorr.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"
#include "security/secp256k1.h"
#include "transport/udp/udp_transport.h"
#include "transport/tcp/tcp_transport.h"
#include "transport/multi_thread.h"
#include "transport/synchro_wait.h"
#include "transport/transport_utils.h"
#include "transport/proto/transport.pb.h"
#include "ip/ip_with_country.h"
#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "network/bootstrap.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal.h"
#include "contract/proto/contract_proto.h"
#include "contract/contract_utils.h"
#include "init/update_vpn_init.h"
#include "client/client_utils.h"
#include "client/proto/client_proto.h"
#include "client/client_universal_dht.h"

namespace lego {

namespace client {

static const uint32_t kDefaultBufferSize = 1024u * 1024u;
static common::Config config;
static std::shared_ptr<ClientUniversalDht> root_dht_{ nullptr };
static const std::string kCheckVersionAccount = common::Encode::HexDecode(
		"e8a1ceb6b807a98a20e3aa10aa2199e47cbbed08c2540bd48aa3e1e72ba6bd99");
static const std::string kClientDownloadUrl = (
		"ios;1.0.3;,"
		"android;1.0.3;,"
		"windows;1.0.3;,"
		"mac;1.0.3;");

VpnClient::VpnClient() {
	check_tx_tick_ = std::make_shared<common::Tick>();
	vpn_nodes_tick_ = std::make_shared<common::Tick>();
	dump_config_tick_ = std::make_shared<common::Tick>();
	dump_bootstrap_tick_ = std::make_shared<common::Tick>();
    paied_vip_info_[0] = std::make_shared<LastPaiedVipInfo>();
    paied_vip_info_[0]->height = 0;
    paied_vip_info_[0]->timestamp = 0;
    paied_vip_info_[0]->amount = 0;
    paied_vip_info_[1] = nullptr;
}

VpnClient::~VpnClient() {
    Destroy();
}

uint16_t VpnClient::UpdateVpnPort(const std::string& dht_key) {
    auto decode_dht_key = common::Encode::HexDecode(dht_key);
    uint16_t min_port = 0;
    uint16_t max_port = 0;
    init::UpdateVpnInit::Instance()->GetPortRangeByDhtKey(
        decode_dht_key, false, &min_port, &max_port);
    return common::GetVpnServerPort(
            decode_dht_key,
            common::TimeUtils::TimestampDays(),
            min_port,
            max_port);
}

std::string VpnClient::UpdateUseVpnNode(
        const std::string& old_ip,
        const std::string& ip,
        const std::string& uid) {
    auto uni_dht = lego::network::DhtManager::Instance()->GetDht(
            lego::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("not found vpn server dht.");
        return "";
    }

    transport::protobuf::Header msg;
    client::ClientProto::CreateUpVpnCount(
            uni_dht->local_node(),
            common::GlobalInfo::Instance()->id(),
            ip,
            old_ip,
            uid,
            msg);
    std::string local_vpn_count_svr = init::UpdateVpnInit::Instance()->local_vpn_count_direct_info();
    common::Split<> svrs(local_vpn_count_svr.c_str(), ',', local_vpn_count_svr.size());
    for (uint32_t i = 0; i < local_vpn_count_svr.size(); ++i) {
        common::Split<> svr(svrs[i], ':', svrs.SubLen(i));
        if (svr.Count() < 2) {
            continue;
        }

        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                svr[0],
                common::StringUtil::ToUint16(svr[1]),
                0,
                msg);
    }

    std::unique_lock<std::mutex> vpn_node_info_lock(vpn_node_info_mutex_);
    vpn_node_info_con_.wait_for(vpn_node_info_lock, std::chrono::seconds(2));
    return vpn_node_info_;
}

std::string VpnClient::VpnConnected() {
    return ((transport::TcpTransport*)(tcp_transport_.get()))->ClearAllConnection();
}

void VpnClient::Destroy() {
    if (udp_transport_ != nullptr) {
        udp_transport_->Stop();
        CLIENT_ERROR("transport stopped");
        udp_transport_ = nullptr;
    }
}

VpnClient* VpnClient::Instance() {
    static VpnClient ins;
    return &ins;
}

std::string VpnClient::GetClientProperty() {
    std::string res = "";
    res += common::StringUtil::Format("%s:%u,", "min_vip_payfor", common::kVpnVipMinPayfor);
    res += common::StringUtil::Format("%s:%u,", "max_vip_payfor", common::kVpnVipMaxPayfor);
    return res;
}

std::string VpnClient::GetNewBoot() {
    auto dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    auto dht_nodes = dht->readonly_dht();
    std::unordered_set<std::string> bootstrap_set;
    for (auto iter = dht_nodes->begin(); iter != dht_nodes->end(); ++iter) {
        std::string node_info = ("id:" +
            (*iter)->public_ip() + ":" +
            std::to_string((*iter)->public_port));
        auto siter = bootstrap_set.find(node_info);
        if (siter != bootstrap_set.end()) {
            continue;
        }
        bootstrap_set.insert(node_info);
    }

    if (!bootstrap_set.empty()) {
        std::string boot_str;
        for (auto iter = bootstrap_set.begin(); iter != bootstrap_set.end(); ++iter) {
            boot_str += *iter + ",";
        }
        return boot_str;
    }

    return "";
}

std::string VpnClient::CheckVersion() {
	return vpn_download_url_;
}

void VpnClient::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() == common::kBlockMessage) {
        HandleBlockMessage(header);
    }

    if (header.type() == common::kContractMessage) {
        HandleContractMessage(header);
    }
}

void VpnClient::HandleBlockMessage(transport::protobuf::Header& header) {
    block::protobuf::BlockMessage block_msg;
    if (!block_msg.ParseFromString(header.data())) {
        return;
    }

    if (block_msg.has_height_res()) {
        HandleHeightResponse(block_msg.height_res());
    }

    if (block_msg.has_block_res()) {
        HandleBlockResponse(block_msg.block_res());
    }

    if (block_msg.has_acc_attr_res()) {
        HandleGetAttrResponse(header, block_msg);
    }

    if (block_msg.has_up_vpn_res()) {
        HandleUpdateVpnCountResponse(header, block_msg);
    }

    if (block_msg.has_account_init_res()) {
        init::UpdateVpnInit::Instance()->UpdateAccountBlockInfo(header.data());
    }
}

void VpnClient::AdReward(const std::string& str) {
    common::Split<> str_splits(str.c_str(), '_', str.size());
    std::string version = common::kAdRewardVersionStr;
    if (str_splits.Count() >= 3) {
        version = str_splits[2];
    }

    transport::protobuf::Header message;
    auto dht = network::UniversalManager::Instance()->GetUniversal(
            lego::network::kUniversalNetworkId);
    if (dht == nullptr) {
        return;
    }

    message.set_client(true);
    message.set_hop_count(2);
    message.set_src_node_id(dht->local_node()->id());
    message.set_src_dht_key(dht->local_node()->dht_key());
    message.set_id(common::GlobalInfo::Instance()->MessageId());
    auto dht_key_mgr = dht::DhtKeyManager(
        common::GlobalInfo::Instance()->network_id(),
        0,
        common::GlobalInfo::Instance()->id());
    message.set_des_dht_key(dht_key_mgr.StrKey());
    message.set_priority(transport::kTransportPriorityLow);
    message.set_type(common::kBlockMessage);
    block::protobuf::BlockMessage block_msg;
    auto attr_req = block_msg.mutable_ad_reward_req();
    attr_req->set_id(common::GlobalInfo::Instance()->id());
    auto gid = common::FixedCreateGID(security::Schnorr::Instance()->str_pubkey() +
            std::to_string(common::TimeUtils::TimestampSeconds() / 10));
    attr_req->set_gid(gid);
    attr_req->set_reward_key(version);
    message.set_data(block_msg.SerializeAsString());
    dht->SendToClosestNode(message);
}

void VpnClient::HandleUpdateVpnCountResponse(
        transport::protobuf::Header& header,
        block::protobuf::BlockMessage& block_msg) {
    std::string vpn_nodes;
    for (int32_t i = 0; i < block_msg.up_vpn_res().vpn_nodes_size(); ++i) {
        vpn_nodes += (block_msg.up_vpn_res().vpn_nodes(i).ip() + ":" +
            std::to_string(block_msg.up_vpn_res().vpn_nodes(i).count())) + ",";
    }

    std::lock_guard<std::mutex> guard(vpn_node_info_mutex_);
    vpn_node_info_ = vpn_nodes;
    vpn_node_info_con_.notify_all();
}

void VpnClient::HandleContractMessage(transport::protobuf::Header& header) {
    contract::protobuf::ContractMessage contract_msg;
    if (!contract_msg.ParseFromString(header.data())) {
        return;
    }

    if (contract_msg.has_get_attr_res()) {
        auto client_bw_res = contract_msg.get_attr_res();
        std::string key = client_bw_res.attr_key();
        common::Split<> key_split(key.c_str(), '_', key.size());
        if (key_split.Count() != 3) {
            return;
        }

        auto today_timestamp = std::to_string(common::TimeUtils::TimestampDays());
        if (today_timestamp != key_split[2]) {
            return;
        }

        try {
            today_used_bandwidth_ = common::StringUtil::ToUint32(client_bw_res.attr_value());
        } catch (...) {
        }
    }
}

void VpnClient::HandleGetAttrResponse(
        transport::protobuf::Header& header,
        block::protobuf::BlockMessage& block_msg) {
    if (paied_vip_info_[paied_vip_valid_idx_]->timestamp == 0) {
        paied_vip_info_[paied_vip_valid_idx_]->timestamp = kInvalidTimestamp;
    }

    auto& attr_res = block_msg.acc_attr_res();
    if (attr_res.block().empty()) {
        return;
    }

    bft::protobuf::Block block;
    if (!block.ParseFromString(attr_res.block())) {
        return;
    }

    // TODO(): check block multi sign, this node must get election blocks
    std::string login_svr_id;
    auto& tx_list = block.tx_list();
    for (int32_t i = tx_list.size() - 1; i >= 0; --i) {
        if (tx_list[i].attr_size() > 0) {
            if (tx_list[i].from() != attr_res.account()) {
                continue;
            }

            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                auto iter = common::GlobalInfo::Instance()->vpn_committee_accounts().find(tx_list[i].to());
                if (tx_list[i].attr(attr_idx).key() == common::kUserPayForVpn &&
                        iter != common::GlobalInfo::Instance()->vpn_committee_accounts().end()) {
                    auto paied_vip_ptr = std::make_shared<LastPaiedVipInfo>();
                    paied_vip_ptr->amount = tx_list[i].amount();
                    paied_vip_ptr->block_hash = block.hash();
                    paied_vip_ptr->height = block.height();
                    paied_vip_ptr->timestamp = block.timestamp();

                    long day_msec = 3600 * 1000 * 24;
                    long days_timestamp = paied_vip_ptr->timestamp / day_msec;
                    long days_cur = common::TimeUtils::TimestampDays();
                    long vip_days = paied_vip_ptr->amount / common::kVpnVipMinPayfor;
                    if (days_timestamp + vip_days > days_cur) {
                        if (vpn_route_network_id_ != network::kVpnRouteVipLevel1NetworkId) {
                            vpn_vip_level_ = common::kVipLevel1;
                            vpn_route_network_id_ = network::kVpnRouteVipLevel1NetworkId;
                        }
                    } else {
                        if (vpn_route_network_id_ != network::kVpnRouteNetworkId) {
                            vpn_vip_level_ = common::kNotVip;
                            vpn_route_network_id_ = network::kVpnRouteNetworkId;
                        }
                    }

                    paied_vip_ptr->to_account = tx_list[i].to();
                    if (paied_vip_valid_idx_ == 0) {
                        paied_vip_info_[1] = paied_vip_ptr;
                        paied_vip_valid_idx_ = 1;
                    } else {
                        paied_vip_info_[0] = paied_vip_ptr;
                        paied_vip_valid_idx_ = 0;
                    }
                }

                if (tx_list[i].attr(attr_idx).key() == common::kCheckVpnVersion) {
                    if (block.height() > vpn_version_last_height_) {
                        vpn_version_last_height_ = block.height();
                        vpn_download_url_ = tx_list[i].attr(attr_idx).value();
                    }
                }
            }
        }
    }
}

void VpnClient::HandleBlockResponse(const block::protobuf::GetTxBlockResponse& block_res) {
    bft::protobuf::Block block;
    if (!block.ParseFromString(block_res.block())) {
        return;
    }

	bool has_local_trans = false;
    std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    std::lock_guard<std::mutex> tmp_map_guard(tx_map_mutex_);
    auto& tx_list = block_ptr->tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        tx_map_[tx_list[i].gid()] = block_ptr;
        if (tx_list[i].from() == common::GlobalInfo::Instance()->id() ||
				tx_list[i].to() == common::GlobalInfo::Instance()->id()) {
            has_local_trans = true;
            break;
		}
    }

	if (has_local_trans) {
		hight_block_map_[block.height()] = block_res.block();
		if (hight_block_map_.size() >= kHeightMaxSize) {
			hight_block_map_.erase(hight_block_map_.begin());
		}
	}
}

void VpnClient::HandleHeightResponse(
        const block::protobuf::AccountHeightResponse& height_res) {
    std::lock_guard<std::mutex> guard(height_set_mutex_);
    for (int32_t i = 0; i < height_res.heights_size(); ++i) {
        local_account_height_set_.insert(height_res.heights(i));
        if (local_account_height_set_.size() > kHeightMaxSize) {
            local_account_height_set_.erase(local_account_height_set_.begin());
        }
    }
}

void VpnClient::SendGetAccountAttrUsedBandwidth() {
    auto uni_dht = lego::network::DhtManager::Instance()->GetDht(
            lego::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string key = (common::kIncreaseVpnBandwidth + "_" +
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) + "_" +
            now_day_timestamp);
    contract::ContractProto::CreateGetAttrRequest(
            uni_dht->local_node(),
            common::GlobalInfo::Instance()->id(),
            key,
            msg);
    uni_dht->SendToClosestNode(msg);
}

std::string VpnClient::CheckFreeBandwidth() {
    SendGetAccountAttrUsedBandwidth();
    return std::to_string(today_used_bandwidth_);
}

void VpnClient::VpnHeartbeat(const std::string& dht_key) {
    CLIENT_ERROR("VpnHeartbeat start");
    transport::protobuf::Header msg;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    ClientProto::CreateVpnHeartbeat(
            root_dht_->local_node(),
            common::Encode::HexDecode(dht_key),
            msg);
    uni_dht->SendToClosestNode(msg);
    CLIENT_ERROR("VpnHeartbeat end");
}

int VpnClient::GetSocket() {
    return 0;
}

int64_t VpnClient::GetBalance() {
    CheckTxExists();
    return init::UpdateVpnInit::Instance()->GetBalance();
}

std::string VpnClient::Transactions(uint32_t begin, uint32_t len) {
    auto blocks_heap = init::UpdateVpnInit::Instance()->GetTxBlocks();
    std::string res_str;
    uint32_t now_len = 0;
    std::vector<std::string> all_tx_vec;
    auto& accounts_map = common::GlobalInfo::Instance()->vpn_committee_accounts();
    auto& share_accounts = common::GlobalInfo::Instance()->share_reward_accounts();
    auto& ad_accounts = common::GlobalInfo::Instance()->watch_ad_reward_accounts();
    auto& mining_accounts = common::GlobalInfo::Instance()->vpn_minning_accounts();
    while (!blocks_heap.empty()) {
        auto timestamp = common::MicTimestampToLiteDatetime(blocks_heap.top().timestamp);
        std::string tx_item;
        if (blocks_heap.top().from == common::GlobalInfo::Instance()->id()) {
            std::string type("2");
            if (blocks_heap.top().type == common::kConsensusPayForCommonVpn) {
                type = "1";  // pay for vpn
            }

            tx_item = (timestamp + "," +
                    type + "," +
                    "-" + std::to_string(blocks_heap.top().amount) + "," +
                    std::to_string(blocks_heap.top().balance) + "," +
                    common::Encode::HexEncode(blocks_heap.top().gid) + "," +
                    std::to_string(blocks_heap.top().type) + "," +
                    std::to_string(blocks_heap.top().status));
        } else {
            std::string type("4");  // transfer in
            auto iter = accounts_map.find(blocks_heap.top().from);
            if (iter != accounts_map.end()) {
                type = "3";  // charge to account
            }

            auto share_iter = share_accounts.find(blocks_heap.top().from);
            if (share_iter != share_accounts.end()) {
                type = "5";  // share reward
            }

            auto ad_iter = ad_accounts.find(blocks_heap.top().from);
            if (ad_iter != ad_accounts.end()) {
                type = "6";  // watch ad reward
            }

            auto minning_iter = mining_accounts.find(blocks_heap.top().from);
            if (minning_iter != mining_accounts.end()) {
                type = "7";  // minning reward
            }

            tx_item = (timestamp + "," +
                    type + "," +
                    std::to_string(blocks_heap.top().amount) + "," +
                    std::to_string(blocks_heap.top().balance) + "," +
                    common::Encode::HexEncode(blocks_heap.top().gid) + "," +
                    std::to_string(blocks_heap.top().type) + "," +
                    std::to_string(blocks_heap.top().status));
        }

        all_tx_vec.push_back(tx_item);
        blocks_heap.pop();
    }

    for (auto iter = all_tx_vec.rbegin(); iter != all_tx_vec.rend(); ++iter) {
        if (res_str.empty()) {
            res_str = *iter;
        } else {
            res_str += ";" + *iter;
        }

        ++now_len;
        if (now_len >= len) {
            break;
        }
    }
 
    return res_str;
}

std::string VpnClient::GetIpCountry(const std::string& ip) {
    std::lock_guard<std::mutex> guard(init_mutex_);
    if (!ip_loaded_) {
        auto geo_path = config_path_ + "/geolite.conf";
        auto geo_country_path = config_path_ + "/geo_country.conf";
        if (ip::IpWithCountry::Instance()->Init(geo_path, geo_country_path) != ip::kIpSuccess) {
            CLIENT_ERROR("init ip failed[%s][%s].", geo_path.c_str(), geo_country_path.c_str());
            printf("init ip failed[%s][%s].\n", geo_path.c_str(), geo_country_path.c_str());
            return "";
        }

        ip_loaded_ = true;
    }

    return ip::IpWithCountry::Instance()->GetCountryCode(ip);
}

std::string VpnClient::Init(
        const std::string& local_ip,
        uint16_t init_type,
        const std::string& bootstrap,
        const std::string& path,
        const std::string& version,
        const std::string& c_private_key) {
    network::Route::Instance()->RegisterMessage(
        common::kServiceMessage,
        std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
        common::kBlockMessage,
        std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
        common::kContractMessage,
        std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    config_path_ = path;
    std::string conf_path = path + "/lego.conf";
    std::string log_conf_path = path + "/log4cpp.properties";
    std::string log_path = path + "/lego.log";
    WriteDefaultLogConf(log_conf_path, log_path);
    log4cpp::PropertyConfigurator::configure(log_conf_path);
    std::string private_key;
    if (ConfigExists(conf_path)) {
        if (!config.Init(conf_path)) {
            CLIENT_ERROR("init config failed!");
            config.Set("lego", "prikey", std::string(""));
        }

        std::string priky("");
        if (!config.Get("lego", "prikey", priky) || priky.empty()) {
            CLIENT_ERROR("config[%s] invalid!", conf_path.c_str());
        } else {
            private_key = common::Encode::HexDecode(priky);
        }
    }

    if (c_private_key.size() == security::kPrivateKeySize * 2) {
        private_key = common::Encode::HexDecode(c_private_key);
    }

    uint16_t local_port = 0;
    if (init_type > 1000) {
        local_port = init_type;
        init_type = dht::kBootstrapInit;
    }

    std::string init_info;
    config.Get("lego", "init_info", init_info);
    std::string init_info1;
    config.Get("lego", "init_info", init_info1);
    config.Get("lego", "first_instasll", first_install_);
    config.Set("lego", "local_ip", local_ip);
    config.Set("lego", "local_port", local_port);
    config.Set("lego", "country", std::string("US"));
    config.Set("lego", "first_node", false);
    config.Set("lego", "client", true);
    config.Set("lego", "bootstrap", bootstrap);
    config.Set("lego", "id", std::string("test_id"));
    std::string boot_net;
    config.Get("lego", "bootstrap_net", boot_net);
    boot_net += "," + bootstrap;
    if (common::GlobalInfo::Instance()->Init(config) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return "ERROR";
    }

    if (SetPriAndPubKey(private_key) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "ERROR";
    }

    config.Set("lego", "prikey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_prikey()));
    config.Set("lego", "pubkey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_pubkey()));
    CLIENT_ERROR("set private key[%s], public key[%s]",
        common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()).c_str(),
        common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey()).c_str());
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
            security::Schnorr::Instance()->str_pubkey_uncompress());
    common::GlobalInfo::Instance()->set_id(account_address);
    config.Set("lego", "id", common::Encode::HexEncode(
            common::GlobalInfo::Instance()->id()));
    std::string vpn_us_nodes;
    config.Get("vpn", "US", vpn_us_nodes);
    std::string route_us_nodes;
    config.Get("route", "US", route_us_nodes);
    common::Split<> ver_split(version.c_str(), '_', version.size());
    if (ver_split.Count() >= 2) {
        std::string tmp_uid(ver_split[1], ver_split.SubLen(1));
        config.Set("lego", "init_uid", tmp_uid);
        config.Set("lego", "version", ver_split[0]);
    } else {
        config.Set("lego", "version", version);
    }

    std::string def_conf;
    config.Get("route", "def_routing", def_conf);
    if (def_conf.empty()) {
        SetDefaultRouting();
        config.Get("route", "def_routing", def_conf);
    }

    uint64_t bTime = common::TimeUtils::TimestampMs();
    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        CLIENT_ERROR("init ecdh create secret key failed!");
        return "ERROR";
    }

    network::DhtManager::Instance();
    if (InitUdpTransport() != kClientSuccess) {
        CLIENT_ERROR("InitUdpTransport failed!");
        return "ERROR";
    }

    CLIENT_ERROR("InitUdpTransport: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    if (InitTcpTransport() != kClientSuccess) {
        CLIENT_ERROR("InitTcpTransport failed!");
        return "ERROR";
    }

    CLIENT_ERROR("InitTcpTransport: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    transport::MultiThreadHandler::Instance()->Init(
            udp_transport_,
            tcp_transport_);
    CLIENT_ERROR("MultiThreadHandler::Instance()->Init: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    if (InitNetworkSingleton(init_type) != kClientSuccess) {
        common::GlobalInfo::Instance()->set_country(common::CountryCode::CN);
        dht::protobuf::InitMessage init_msg;
        if (init_msg.ParseFromString(common::Encode::HexDecode(init_info))) {
            init::UpdateVpnInit::Instance()->BootstrapInit(init_msg);
        }
        CLIENT_ERROR("InitNetworkSingleton failed!");
    } else {
        init::UpdateVpnInit::Instance()->GetInitInfo(&init_info);
        config.Set("lego", "init_info", init_info);
        config.DumpConfig(conf_path);
    }

    CLIENT_ERROR("InitNetworkSingleton: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    check_tx_tick_->CutOff(kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
    CLIENT_ERROR("CheckTxExists: %lu!", (common::TimeUtils::TimestampMs() - bTime));
    vpn_download_url_ = init::UpdateVpnInit::Instance()->GetVersion();
    vpn_route_network_id_ = network::kVpnRouteNetworkId;
    for (int i = 0; i < 5; ++i) {
        if (init::UpdateVpnInit::Instance()->InitSuccess()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(300ull));
    }

#ifdef MAKE_CLIENT_LIB
    if (common::GlobalInfo::Instance()->is_client()) {
        common::global_stop = true;
    }
#endif

    return (common::global_code_to_country_map[common::GlobalInfo::Instance()->country()] +
            "," +
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) +
            "," +
            common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()) +
            "," + def_conf +
            "," + init::UpdateVpnInit::Instance()->init_vpn_count_info());
}

void VpnClient::UpdateCountryCode(const std::string& country) {

}

std::string VpnClient::ResetPrivateKey(const std::string& prikey) {
    if (prikey.size() != security::kPrivateKeySize * 2) {
        return "ERROR";
    }

    std::string private_key = common::Encode::HexDecode(prikey);
    if (SetPriAndPubKey(private_key) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "ERROR";
    }

    config.Set("lego", "prikey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_prikey()));
    config.Set("lego", "pubkey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_pubkey()));
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Schnorr::Instance()->str_pubkey_uncompress());
    common::GlobalInfo::Instance()->set_id(account_address);
    
    {
        std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
        hight_block_map_.clear();
        local_account_height_set_.clear();
    }

    {
        std::lock_guard<std::mutex> guard(height_set_mutex_);
        local_account_height_set_.clear();
    }

    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        tx_map_.clear();
    }

    today_used_bandwidth_ = -1;
    paied_vip_info_[0] = std::make_shared<LastPaiedVipInfo>();
    paied_vip_info_[0]->height = 0;
    paied_vip_info_[0]->timestamp = 0;
    paied_vip_info_[1] = nullptr;
    paied_vip_valid_idx_ = 0;
    check_times_ = 0;
    return common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey())
            + "," + common::Encode::HexEncode(account_address);
}

std::string VpnClient::GetPublicKey() {
    return common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey());
}

std::string VpnClient::GetSecretKey(const std::string& peer_pubkey) {
    std::string sec_key;
    security::PublicKey pubkey(peer_pubkey);
    if (security::EcdhCreateKey::Instance()->CreateKey(
            pubkey,
            sec_key) != security::kSecuritySuccess) {
        return "ERROR";
    }

    return common::Encode::HexEncode(sec_key);
}

bool VpnClient::SetFirstInstall() {
    first_install_ = true;
    config.Set("lego", "first_instasll", first_install_);
    config.DumpConfig(config_path_ + "/lego.conf");
    return true;
}

bool VpnClient::ConfigExists(const std::string& conf_path) {
    FILE* file = NULL;
    file = fopen(conf_path.c_str(), "r");
    if (file == NULL) {
        return false;
    }

    struct stat buf;
    int fd = fileno(file);
    fstat(fd, &buf);
    fclose(file);
    if (buf.st_size <= 0) {
        return false;
    }
    return true;
}

void VpnClient::WriteDefaultLogConf(
        const std::string& log_conf_path,
        const std::string& log_path) {
    FILE* file = NULL;
    file = fopen(log_conf_path.c_str(), "w");
    if (file == NULL) {
        return;
    }
    std::string log_str = ("# log4cpp.properties\n"
        "log4cpp.rootCategory = WARN\n"
        "log4cpp.category.sub1 = WARN, programLog\n"
        "log4cpp.appender.rootAppender = ConsoleAppender\n"
        "log4cpp.appender.rootAppender.layout = PatternLayout\n"
        "log4cpp.appender.rootAppender.layout.ConversionPattern = %d [%p] %m%n\n"
        "log4cpp.appender.programLog = RollingFileAppender\n"
        "log4cpp.appender.programLog.fileName = ") + log_path + "\n" +
        std::string("log4cpp.appender.programLog.maxFileSize = 1073741824\n"
        "log4cpp.appender.programLog.maxBackupIndex = 1\n"
        "log4cpp.appender.programLog.layout = PatternLayout\n"
        "log4cpp.appender.programLog.layout.ConversionPattern = %d [%p] %m%n\n");
    fwrite(log_str.c_str(), log_str.size(), 1, file);
    fclose(file);
}

std::string VpnClient::GetVpnServerNodes(
        const std::string& country,
        const std::string& key,
        uint32_t count,
        bool route,
        bool is_vip,
        std::vector<VpnServerNodePtr>& nodes) {
    if (country == "ALL") {
        return init::UpdateVpnInit::Instance()->GetAllNodes(is_vip);
    }

    if (!route) {
        if (!key.empty()) {
            init::UpdateVpnInit::Instance()->GetVlanVpnNode(country, nodes);
        } else {
            init::UpdateVpnInit::Instance()->GetVpnSvrNodes(is_vip, country, nodes);
        }
    } else {
        if (!key.empty()) {
            init::UpdateVpnInit::Instance()->GetVlanRouteNode(country, key, nodes);
        } else {
            init::UpdateVpnInit::Instance()->GetRouteSvrNodes(is_vip, country, nodes);
        }
    }

    if (!nodes.empty()) {
        return "OK";
    }

    return "get vpn nodes failed!";
}

int VpnClient::InitTcpTransport() {
    std::string client_spec = "0.0.0.0:0";
    tcp_transport_ = std::make_shared<transport::TcpTransport>(
            client_spec,
            128,
            false);
    if (tcp_transport_->Init() != transport::kTransportSuccess) {
        CLIENT_ERROR("init tcp transport failed!");
        return kClientError;
    }

    if (tcp_transport_->Start(false) != transport::kTransportSuccess) {
        CLIENT_ERROR("start udp transport failed!");
        return kClientError;
    }

    return kClientSuccess;
}

int VpnClient::InitUdpTransport() {
    udp_transport_ = std::make_shared<transport::UdpTransport>(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            send_buff_size_,
            recv_buff_size_);
    if (udp_transport_->Init() != transport::kTransportSuccess) {
        CLIENT_ERROR("init udp transport failed!");
        return kClientError;
    }

    if (udp_transport_->Start(false) != transport::kTransportSuccess) {
        CLIENT_ERROR("start udp transport failed!");
        return kClientError;
    }
    return kClientSuccess;
}

int VpnClient::ResetTransport(const std::string& ip, uint16_t port) {
    transport::TransportPtr tmp_udp_transport = std::make_shared<transport::UdpTransport>(
            ip,
            port,
            send_buff_size_,
            recv_buff_size_);
    if (tmp_udp_transport->Init() != transport::kTransportSuccess) {
        CLIENT_ERROR("init udp transport failed!");
        return -1;
    }

    if (tmp_udp_transport->Start(false) != transport::kTransportSuccess) {
        CLIENT_ERROR("start udp transport failed!");
        return -1;
    }
    transport::MultiThreadHandler::Instance()->ResetTransport(tmp_udp_transport);
    common::GlobalInfo::Instance()->set_config_local_ip(ip);
    common::GlobalInfo::Instance()->set_config_local_port(port);
    udp_transport_ = tmp_udp_transport;
    return tmp_udp_transport->GetSocket();
}

int VpnClient::SetPriAndPubKey(const std::string& prikey) {
    std::shared_ptr<security::PrivateKey> prikey_ptr{ nullptr };
    if (!prikey.empty()) {
        security::PrivateKey private_key(prikey);
        prikey_ptr = std::make_shared<security::PrivateKey>(private_key);
    } else {
        security::PrivateKey private_key;
        prikey_ptr = std::make_shared<security::PrivateKey>(private_key);
    }
    security::PublicKey pubkey(*(prikey_ptr.get()));
    auto pubkey_ptr = std::make_shared<security::PublicKey>(pubkey);
    security::Schnorr::Instance()->set_prikey(prikey_ptr);

    std::string pubkey_str;
    pubkey.Serialize(pubkey_str, false);
    std::string account_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
    common::GlobalInfo::Instance()->set_id(account_id);
    return kClientSuccess;
}

int VpnClient::InitNetworkSingleton(uint32_t init_type) {
    if (network::Bootstrap::Instance()->Init(config) != network::kNetworkSuccess) {
        CLIENT_ERROR("init bootstrap failed!");
        return kClientError;
    }

    config.Set("lego", "get_init_msg", init_type);
    if (network::UniversalManager::Instance()->CreateUniversalNetwork(
            config,
            udp_transport_) != network::kNetworkSuccess) {
        CLIENT_ERROR("create universal network failed!");
        return kClientError;
    }

    config.Set("lego", "get_init_msg", dht::kBootstrapNoInit);
    return CreateClientUniversalNetwork();
}

int VpnClient::CreateClientUniversalNetwork() {
    dht::DhtKeyManager dht_key(
            network::kVpnNetworkId,
            common::GlobalInfo::Instance()->country(),
            common::GlobalInfo::Instance()->id());
    dht::NodePtr local_node = std::make_shared<dht::Node>(
            common::GlobalInfo::Instance()->id(),
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            client_mode_,
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            security::Schnorr::Instance()->str_pubkey(),
            common::GlobalInfo::Instance()->node_tag());
    NETWORK_ERROR("create universal network[%s][%d][%s]",
            common::GlobalInfo::Instance()->id().c_str(),
            common::GlobalInfo::Instance()->id().size(),
            common::Encode::HexEncode(dht_key.StrKey()).c_str());
    local_node->first_node = common::GlobalInfo::Instance()->config_first_node();
    root_dht_ = std::make_shared<ClientUniversalDht>(udp_transport_, local_node);
    root_dht_->Init();
    auto base_dht = std::dynamic_pointer_cast<dht::BaseDht>(root_dht_);
    network::DhtManager::Instance()->RegisterDht(network::kVpnNetworkId, base_dht);
    return kClientSuccess;
}

std::string VpnClient::CheckVip() {
    return (std::to_string(init::UpdateVpnInit::Instance()->max_pay_for_vpn_tm()) +
            "," + std::to_string(init::UpdateVpnInit::Instance()->max_pay_for_vpn_amount()));
}

void VpnClient::GetVpnVersion() {
}

std::string VpnClient::PayForVPN(const std::string& to, const std::string& gid, uint64_t amount) {
    if (to.empty() || amount <= 0) {
        return "ERROR";
    }

    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return "ERROR";
    }
    auto tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    if (gid.size() == 32 * 2) {
        tx_gid = common::Encode::HexDecode(gid);
    }

    std::string to_addr = common::Encode::HexDecode(to);
    std::map<std::string, std::string> attrs = {
        { common::kUserPayForVpn, "reserve" }
    };

    uint32_t type = common::kConsensusPayForCommonVpn;
    ClientProto::CreateTransactionWithAttr(
            uni_dht->local_node(),
            tx_gid,
            to_addr,
            amount,
            type,
            contract::kContractVpnPayfor,
            attrs,
            msg);
    network::Route::Instance()->Send(msg);
    return common::Encode::HexEncode(tx_gid);
}

void VpnClient::SendGetAccountAttrLastBlock(
        const std::string& attr,
        const std::string& account,
        uint64_t height) {
    uint64_t rand_num = 0;
    auto uni_dht = lego::network::DhtManager::Instance()->GetDht(
        lego::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    client::ClientProto::AccountAttrRequest(
            uni_dht->local_node(),
            account,
            attr,
            height,
            msg);
    network::Route::Instance()->Send(msg);
}

std::string VpnClient::Transaction(const std::string& to, uint64_t amount, std::string& tx_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("Transaction end error");
        return "ERROR";
    }

    if (tx_gid.size() == 32 * 2) {
        tx_gid = common::Encode::HexDecode(tx_gid);
    } else {
        if (!to.empty()) {
            tx_gid = common::CreateGID(common::GlobalInfo::Instance()->id());
        } else {
            tx_gid = common::GlobalInfo::Instance()->id();
        }
    }

    std::string to_addr;
    if (!to.empty()) {
        to_addr = common::Encode::HexDecode(to);
    }

    uint32_t type = common::kConsensusTransaction;
    if (to.empty()) {
        type = common::kConsensusCreateAcount;
    }

    ClientProto::CreateTxRequest(
            uni_dht->local_node(),
            tx_gid,
            to_addr,
            amount,
            rand_num,
            type,
            msg);
    network::Route::Instance()->Send(msg);
    tx_gid = common::Encode::HexEncode(tx_gid);
    CLIENT_ERROR("transaction gid: %s, from: %s, to: %s, amount: %llu",
        tx_gid.c_str(),
        common::Encode::HexEncode(common::GlobalInfo::Instance()->id()).c_str(),
        common::Encode::HexEncode(to_addr).c_str(),
        amount);
    return "OK";
}

void VpnClient::CheckTxExists() {
    auto now_tm = common::TimeUtils::TimestampMs();
    if (now_tm - prv_get_init_tm_ < 3000llu) {
        return;
    }

    prv_get_init_tm_ = now_tm;
    GetTxBlocksFromBftNetwork();
//     if (GetBalance() == -1) {
//         check_tx_tick_->CutOff(kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
//     } else {
//         check_tx_tick_->CutOff(5 * kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
//     }
}

void VpnClient::GetTxBlocksFromBftNetwork() {
    transport::protobuf::Header message;
    auto dht = network::UniversalManager::Instance()->GetUniversal(lego::network::kUniversalNetworkId);
    if (dht == nullptr) {
        return;
    }

    message.set_client(common::GlobalInfo::Instance()->is_client());
    message.set_hop_count(0);
    message.set_src_node_id(dht->local_node()->id());
    message.set_src_dht_key(dht->local_node()->dht_key());
    message.set_id(common::GlobalInfo::Instance()->MessageId());
    auto dht_key_mgr = dht::DhtKeyManager(
        common::GlobalInfo::Instance()->network_id(),
        0,
        common::GlobalInfo::Instance()->id());
    message.set_des_dht_key(dht_key_mgr.StrKey());
    message.set_priority(transport::kTransportPriorityLow);
    message.set_type(common::kBlockMessage);
    block::protobuf::BlockMessage block_msg;
    auto attr_req = block_msg.mutable_account_init_req();
    attr_req->set_id(common::GlobalInfo::Instance()->id());
    attr_req->set_count(16);
    attr_req->set_height(init::UpdateVpnInit::Instance()->GetMaxHeight());
    message.set_data(block_msg.SerializeAsString());
    dht->SendToClosestNode(message);
}

int VpnClient::VpnLogin(
        const std::string& svr_account,
        const std::vector<std::string>& route_vec,
        std::string& login_gid) {
    CLIENT_ERROR("VpnLogin start");
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
			network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("VpnLogin error");
        return kClientError;
    }
    login_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    uint32_t type = common::kConsensusTransaction;
    ClientProto::CreateVpnLoginRequest(
            uni_dht->local_node(),
            login_gid,
            common::Encode::HexDecode(svr_account),
            route_vec,
            msg);
    network::Route::Instance()->Send(msg);
    login_gid = common::Encode::HexEncode(login_gid);
    CLIENT_ERROR("sent vpn login request: %s", svr_account.c_str());
    CLIENT_ERROR("VpnLogin end");
    return kClientSuccess;
}

int VpnClient::VpnLogout() {
    return kClientSuccess;
}

bft::protobuf::BlockPtr VpnClient::GetBlockWithGid(const std::string& tx_gid) {
    CLIENT_ERROR("GetBlockWithGid start");
    auto tmp_gid = common::Encode::HexDecode(tx_gid);
    std::lock_guard<std::mutex> guard(tx_map_mutex_);
    auto iter = tx_map_.find(tmp_gid);
    if (iter != tx_map_.end()) {
        if (iter->second == nullptr) {
            CLIENT_ERROR("GetBlockWithGid 0");
            return nullptr;
        }

        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        return tmp_ptr;
    } else {
        tx_map_[tmp_gid] = nullptr;
        SendGetBlockWithGid(tmp_gid, true);
    }
    CLIENT_ERROR("GetBlockWithGid end");
    return nullptr;
}

bft::protobuf::BlockPtr VpnClient::GetBlockWithHash(const std::string& block_hash) {
    CLIENT_ERROR("GetBlockWithHash start");
    auto dec_hash = common::Encode::HexDecode(block_hash);
    auto tmp_gid = std::string("b_") + dec_hash;
    std::lock_guard<std::mutex> guard(tx_map_mutex_);
    auto iter = tx_map_.find(tmp_gid);
    if (iter != tx_map_.end()) {
        if (iter->second == nullptr) {
            CLIENT_ERROR("GetBlockWithHash end 1");
            return nullptr;
        }

        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        return tmp_ptr;
    } else {
        tx_map_[tmp_gid] = nullptr;
        SendGetBlockWithGid(dec_hash, false);
    }
    CLIENT_ERROR("GetBlockWithHash end");
    return nullptr;
}

void VpnClient::SendGetBlockWithGid(const std::string& str, bool is_gid) {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }
    transport::protobuf::Header msg;
    ClientProto::GetBlockWithTxGid(uni_dht->local_node(), str, is_gid, true, msg);
    uni_dht->SendToClosestNode(msg);
}

void VpnClient::GetAccountHeight() {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }
    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Schnorr::Instance()->str_pubkey_uncompress());
    ClientProto::GetAccountHeight(uni_dht->local_node(), msg, account_address);
    uni_dht->SendToClosestNode(msg);
}

void VpnClient::GetAccountBlockWithHeight() {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }

    std::set<uint64_t> height_set;
    {
        std::lock_guard<std::mutex> guard(height_set_mutex_);
        height_set = local_account_height_set_;
    }

    uint32_t sended_req = 0;
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Schnorr::Instance()->str_pubkey_uncompress());
    for (auto iter = height_set.rbegin(); iter != height_set.rend(); ++iter) {
        auto height = *iter;
        {
            auto tmp_iter = hight_block_map_.find(height);
            if (tmp_iter != hight_block_map_.end()) {
                continue;
            }
        }
        transport::protobuf::Header msg;
        uni_dht->SetFrequently(msg);
        ClientProto::GetBlockWithHeight(uni_dht->local_node(), account_address, height, msg);
        uni_dht->SendToClosestNode(msg);
        ++sended_req;
        if (sended_req > 30) {
            break;
        }
    }
}

void VpnClient::DumpNodeToConfig() {
    DumpVpnNodes();
    DumpRouteNodes();
    VipDumpVpnNodes();
    VipDumpRouteNodes();
    config.DumpConfig(config_path_ + "/lego.conf");
    dump_config_tick_->CutOff(
            10ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpNodeToConfig, this));
}

void VpnClient::DumpVpnNodes() {
    std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    std::string country_list;
    auto tp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count();
    for (auto iter = vpn_nodes_map_.begin(); iter != vpn_nodes_map_.end(); ++iter) {
#ifdef IOS_PLATFORM
		if (iter->first == "CN") {
			continue;
		}
#endif
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->svr_port) + "," +
                    std::to_string(timestamp));
            conf_str += tmp_str + ";";
        }
        config.Set("vpn", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("vpn", "country", country_list);
}

void VpnClient::DumpRouteNodes() {
    std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
    std::string country_list;
    for (auto iter = route_nodes_map_.begin(); iter != route_nodes_map_.end(); ++iter) {
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->route_port));
            conf_str += tmp_str + ";";
        }
        config.Set("route", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("route", "country", country_list);
}

void VpnClient::VipDumpVpnNodes() {
    std::lock_guard<std::mutex> guard(vip_vpn_nodes_map_mutex_);
    std::string country_list;
    auto tp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count();
    for (auto iter = vip_vpn_nodes_map_.begin(); iter != vip_vpn_nodes_map_.end(); ++iter) {
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->svr_port) + "," +
                    std::to_string(timestamp));
            conf_str += tmp_str + ";";
        }
        config.Set("vip_vpn", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("vip_vpn", "country", country_list);
}

void VpnClient::VipDumpRouteNodes() {
    std::lock_guard<std::mutex> guard(vip_route_nodes_map_mutex_);
    std::string country_list;
    for (auto iter = vip_route_nodes_map_.begin(); iter != vip_route_nodes_map_.end(); ++iter) {
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->route_port));
            conf_str += tmp_str + ";";
        }
        config.Set("vip_route", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("vip_route", "country", country_list);
}

void VpnClient::DumpBootstrapNodes() {
    auto dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    auto dht_nodes = dht->readonly_dht();
    std::unordered_set<std::string> bootstrap_set;
    for (auto iter = dht_nodes->begin(); iter != dht_nodes->end(); ++iter) {
        std::string node_info = ("id:" +
                (*iter)->public_ip() + ":" +
                std::to_string((*iter)->public_port));
        auto siter = bootstrap_set.find(node_info);
        if (siter != bootstrap_set.end()) {
            continue;
        }
        bootstrap_set.insert(node_info);
    }

    if (!bootstrap_set.empty()) {
        std::string boot_str;
        for (auto iter = bootstrap_set.begin(); iter != bootstrap_set.end(); ++iter) {
            boot_str += *iter + ",";
        }
        config.Set("lego", "bootstrap_net", boot_str);
        config.DumpConfig(config_path_ + "/lego.conf");
    }

    dump_bootstrap_tick_->CutOff(
            10ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpBootstrapNodes, this));
}

std::string VpnClient::GetRouting(const std::string& start, const std::string& end) {
    return "";
}

int VpnClient::SetDefaultRouting() {
    std::string def_conf = "PH:CN;PK:CN;VN:CN;BD:CN;ID:CN;MY:SG;CN:CN";
    if (!config.Set("route", "def_routing", def_conf)) {
        CLIENT_ERROR("set default config for [%s] failed", def_conf.c_str());
        return kClientError;
    }
    return kClientSuccess;
}

std::string VpnClient::GetDefaultRouting() {
    std::string def_conf;
    config.Get("route", "def_routing", def_conf);
    return def_conf;
}

}  // namespace client

}  // namespace lego
