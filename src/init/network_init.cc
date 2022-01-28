#include "stdafx.h"
#include "init/network_init.h"

#include <functional>

#include "bft/bft_manager.h"
#include "bft/proto/bft_proto.h"
#include "block/block_manager.h"
#include "block/account_manager.h"
#include "common/global_info.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/random.h"
#include "client/vpn_client.h"
#include "db/db.h"
#include "election/elect_dht.h"
#include "election/proto/elect_proto.h"
#include "election/elect_manager.h"
#include "http/http_server.h"
#include "ip/ip_with_country.h"
#include "init/init_utils.h"
#include "init/genesis_block_init.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/bootstrap.h"
#include "network/route.h"
#include "security/ecdh_create_key.h"
#include "security/secp256k1.h"
#include "sync/key_value_sync.h"
#include "transport/multi_thread.h"
#include "transport/udp/udp_transport.h"
#include "transport/tcp/tcp_transport.h"
#include "transport/transport_utils.h"
#include "transport/http/http_transport.h"
#include "tvm/execution.h"
#include "tvm/tvm_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace init {

static const std::string kDefaultConfigPath("./conf/tenon.conf");
static const uint32_t kDefaultBufferSize = 1024u * 1024u;
static const std::string kInitJoinWaitingPoolDbKey = "__kInitJoinWaitingPoolDbKey";

NetworkInit::NetworkInit() {}

NetworkInit::~NetworkInit() {
    Destroy();
}

int NetworkInit::Init(int argc, char** argv) {
    auto b_time = common::TimeUtils::TimestampMs();
    // std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        INIT_ERROR("network inited!");
        return kInitError;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        INIT_ERROR("init ip config with args failed!");
        return kInitError;
    }

    if (InitConfigWithArgs(argc, argv) != kInitSuccess) {
        INIT_ERROR("init config with args failed!");
        return kInitError;
    }

    if (SetPriAndPubKey("") != kInitSuccess) {
        INIT_ERROR("set node private and public key failed!");
        return kInitError;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        INIT_ERROR("init global info failed!");
        return kInitError;
    }

    if (security::Security::Instance()->str_pubkey().empty()) {
        INIT_ERROR("create security public key failed, empty!");
        return kInitError;
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        INIT_ERROR("init ecdh create secret key failed!");
        return kInitError;
    }

    common::ParserArgs parser_arg;
    if (ParseParams(argc, argv, parser_arg) != kInitSuccess) {
        INIT_ERROR("parse params failed!");
        return kInitError;
    }

    int genesis_check = GenesisCmd(parser_arg);
    if (genesis_check != -1) {
        block::AccountManager::Instance()->FlushPoolHeightTreeToDb();
        return genesis_check;
    }

    if (tvm::Execution::Instance()->Init() != tvm::kTvmSuccess) {
        INIT_ERROR("init tvm failed!");
        return kInitError;
    }

    network::DhtManager::Instance();
    network::Route::Instance();
    vss::VssManager::Instance();
    if (InitUdpTransport() != kInitSuccess) {
        INIT_ERROR("init udp transport failed!");
        return kInitError;
    }

    if (InitTcpTransport() != kInitSuccess) {
        INIT_ERROR("init tcp transport failed!");
        return kInitError;
    }

    transport::MultiThreadHandler::Instance()->Init(
            transport_,
            tcp_transport_);
    if (InitNetworkSingleton() != kInitSuccess) {
        INIT_ERROR("InitNetworkSingleton failed!");
        return kInitError;
    }

    if (InitBlock(conf_) != kInitSuccess) {
        INIT_ERROR("init block failed!");
        return kInitError;
    }

    // check if is any consensus shard or root node or join in waiting pool
    if (CheckJoinWaitingPool() != kInitSuccess) {
        INIT_ERROR("CheckJoinWaitingPool failed!");
        return kInitError;
    }

    uint32_t net_id = common::GlobalInfo::Instance()->network_id();
    if (net_id >= network::kConsensusShardEndNetworkId &&
            net_id < network::kConsensusWaitingShardEndNetworkId) {
        net_id -= network::kConsensusWaitingShardOffset;
    } else if (net_id >= network::kRootCongressNetworkId &&
            net_id <= network::kConsensusShardEndNetworkId) {
        auto st = db::Db::Instance()->Put(
            kInitJoinWaitingPoolDbKey,
            std::to_string(net_id + network::kConsensusWaitingShardOffset));
        if (!st.ok()) {
            INIT_ERROR("db::Db::Instance()->Put network[%u] failed!", net_id);
            return kInitError;
        }
    } else {
        // not consensus node not allowed
        return kInitError;
    }

    if (block::AccountManager::Instance()->Init(net_id) != block::kBlockSuccess) {
        return kInitError;
    }

    std::string http_ip = "0.0.0.0";
    uint16_t http_port = 0;
    conf_.Get("tenon", "http_ip", http_ip);
    if (conf_.Get("tenon", "http_port", http_port) && http_port != 0) {
        if (http::HttpServer::Instance()->Init(http_ip.c_str(), http_port, 2) != 0) {
            INIT_ERROR("init http server failed! %s:%d", http_ip.c_str(), http_port);
            return kInitError;
        }

        http::HttpServer::Instance()->Start();
    }

    if (InitCommand() != kInitSuccess) {
        INIT_ERROR("InitCommand failed!");
        return kInitError;
    }

    if (InitBft() != kInitSuccess) {
        INIT_ERROR("int bft failed!");
        return kInitError;
    }

    sync::KeyValueSync::Instance();
    std::string tx_gid;
    client::VpnClient::Instance()->Transaction("", 0, tx_gid);
    inited_ = true;
    cmd_.Run();
    return kInitSuccess;
}

int NetworkInit::CheckJoinWaitingPool() {
    if (common::GlobalInfo::Instance()->data_service_node_for_net_id() > 0) {
        if (elect::ElectManager::Instance()->Join(
                common::GlobalInfo::Instance()->data_service_node_for_net_id() +
                network::kConsensusWaitingShardOffset) != elect::kElectSuccess) {
            INIT_ERROR("join waiting pool network[%u] failed!",
                common::GlobalInfo::Instance()->data_service_node_for_net_id() +
                network::kConsensusWaitingShardOffset);
            return kInitError;
        }

        common::GlobalInfo::Instance()->set_network_id(
            common::GlobalInfo::Instance()->data_service_node_for_net_id() +
            network::kConsensusWaitingShardOffset);
        return kInitSuccess;
    }

    if (common::GlobalInfo::Instance()->network_id() != common::kInvalidUint32) {
        INIT_INFO("init with network id: %u", common::GlobalInfo::Instance()->network_id());
        return kInitSuccess;
    }

    std::string waiting_netid_str;
    uint32_t waiting_network_id = common::kInvalidUint32;
    auto st = db::Db::Instance()->Get(kInitJoinWaitingPoolDbKey, &waiting_netid_str);
    if (st.ok()) {
        if (!common::StringUtil::ToUint32(waiting_netid_str, &waiting_network_id)) {
            return kInitError;
        }
    }

    if ((waiting_network_id < network::kRootCongressWaitingNetworkId ||
            waiting_network_id >= network::kConsensusWaitingShardEndNetworkId)) {
        auto valid_network_ids = elect::ElectManager::Instance()->valid_shard_networks();
        valid_network_ids.insert(network::kRootCongressNetworkId);
        valid_network_ids.insert(network::kConsensusShardBeginNetworkId);
        std::vector<uint32_t> valid_ids(valid_network_ids.begin(), valid_network_ids.end());
        auto rand_idx = common::Random::RandomUint32() % valid_ids.size();
        waiting_network_id = valid_ids[rand_idx] + network::kConsensusWaitingShardOffset;
    }

    if (elect::ElectManager::Instance()->Join(waiting_network_id) != elect::kElectSuccess) {
        INIT_ERROR("join waiting pool network[%u] failed!", waiting_network_id);
        return kInitError;
    }

    if (!st.ok()) {
        st = db::Db::Instance()->Put(kInitJoinWaitingPoolDbKey, std::to_string(waiting_network_id));
        if (!st.ok()) {
            INIT_ERROR("db::Db::Instance()->Put network[%u] failed!", waiting_network_id);
            return kInitError;
        }
    }

    common::GlobalInfo::Instance()->set_network_id(waiting_network_id);
    INIT_INFO("init with network id: %u", waiting_network_id);
    return kInitSuccess;
}

int NetworkInit::GenesisCmd(common::ParserArgs& parser_arg) {
    if (parser_arg.Has("U")) {
        conf_.Set("db", "path", std::string("./root_db"));
        if (InitBlock(conf_) != kInitSuccess) {
            INIT_ERROR("init block failed!");
            return kInitError;
        }

        init::GenesisBlockInit genesis_block;
        std::vector<dht::NodePtr> root_genesis_nodes;
        if (parser_arg.Has("1")) {
            std::string value;
            if (parser_arg.Get("1", value) != common::kParseSuccess) {
                return kInitError;
            }

            common::Split<2048> nodes_split(value.c_str(), ',', value.size());
            for (uint32_t i = 0; i < nodes_split.Count(); ++i) {
                common::Split<> node_info(nodes_split[i], ':', nodes_split.SubLen(i));
                if (node_info.Count() != 3) {
                    continue;
                }

                auto node_ptr = std::make_shared<dht::Node>();
                node_ptr->set_pubkey(common::Encode::HexDecode(node_info[0]));
                node_ptr->set_public_ip(node_info[1]);
                if (!common::StringUtil::ToUint16(node_info[2], &node_ptr->public_port)) {
                    continue;
                }

                root_genesis_nodes.push_back(node_ptr);
            }
        }

        std::vector<dht::NodePtr> cons_genesis_nodes;
        if (parser_arg.Has("2")) {
            std::string value;
            if (parser_arg.Get("2", value) != common::kParseSuccess) {
                return kInitError;
            }

            common::Split<2048> nodes_split(value.c_str(), ',', value.size());
            for (uint32_t i = 0; i < nodes_split.Count(); ++i) {
                common::Split<> node_info(nodes_split[i], ':', nodes_split.SubLen(i));
                if (node_info.Count() != 3) {
                    continue;
                }

                auto node_ptr = std::make_shared<dht::Node>();
                node_ptr->set_pubkey(common::Encode::HexDecode(node_info[0]));
                node_ptr->set_public_ip(node_info[1]);
                if (!common::StringUtil::ToUint16(node_info[2], &node_ptr->public_port)) {
                    continue;
                }

                cons_genesis_nodes.push_back(node_ptr);
            }
        }

        if (genesis_block.CreateGenesisBlocks(
                network::kRootCongressNetworkId,
                root_genesis_nodes,
                cons_genesis_nodes) != 0) {
            return kInitError;
        }

        return kInitSuccess;
    }

    if (parser_arg.Has("S")) {
        conf_.Set("db", "path", std::string("./shard_db"));
        if (InitBlock(conf_) != kInitSuccess) {
            INIT_ERROR("init block failed!");
            return kInitError;
        }

        init::GenesisBlockInit genesis_block;
        std::vector<dht::NodePtr> root_genesis_nodes;
        std::vector<dht::NodePtr> cons_genesis_nodes;
        if (genesis_block.CreateGenesisBlocks(
                network::kConsensusShardBeginNetworkId,
                root_genesis_nodes,
                cons_genesis_nodes) != 0) {
            return kInitError;
        }

        return kInitSuccess;
    }

    return -1;
}

void NetworkInit::Destroy() {
    common::global_stop = true;

    if (tcp_transport_ != nullptr) {
        tcp_transport_->Stop();
    }

    if (transport_ != nullptr) {
        transport_->Stop();
    }

    if (http_transport_ != nullptr) {
        http_transport_->Stop();
    }
}

int NetworkInit::InitBft() {
    bft::BftManager::Instance();
    return kInitSuccess;
}

int NetworkInit::InitUdpTransport() {
    uint32_t send_buff_size = kDefaultUdpSendBufferSize;
    conf_.Get("tenon", "send_buff_size", send_buff_size);
    uint32_t recv_buff_size = kDefaultUdpRecvBufferSize;
    conf_.Get("tenon", "recv_buff_size", recv_buff_size);
    assert(send_buff_size > kDefaultBufferSize);
    assert(recv_buff_size > kDefaultBufferSize);
    transport_ = std::make_shared<transport::UdpTransport>(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            send_buff_size,
            recv_buff_size);
    if (transport_->Init() != transport::kTransportSuccess) {
        INIT_ERROR("init udp transport failed!");
        return kInitError;
    }

    if (transport_->Start(false) != transport::kTransportSuccess) {
        INIT_ERROR("start udp transport failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitTcpTransport() {
    uint32_t send_buff_size = kDefaultTcpSendBufferSize;
    conf_.Get("tenon", "tcp_send_buff_size", send_buff_size);
    uint32_t recv_buff_size = kDefaultTcpRecvBufferSize;
    conf_.Get("tenon", "tcp_recv_buff_size", recv_buff_size);
    assert(send_buff_size > kDefaultBufferSize);
    assert(recv_buff_size > kDefaultBufferSize);
    tcp_transport_ = std::make_shared<transport::TcpTransport>(
            common::GlobalInfo::Instance()->tcp_spec(),
            128,
            true);
    if (tcp_transport_->Init() != transport::kTransportSuccess) {
        INIT_ERROR("init udp transport failed!");
        return kInitError;
    }

    if (tcp_transport_->Start(false) != transport::kTransportSuccess) {
        INIT_ERROR("start udp transport failed!");
        return kInitError;
    }

    return kInitSuccess;
}

int NetworkInit::InitHttpTransport() {
    http_transport_ = std::make_shared<transport::HttpTransport>();
    if (http_transport_->Init() != transport::kTransportSuccess) {
        INIT_ERROR("init http transport failed!");
        return kInitError;
    }

    if (http_transport_->Start(false) != transport::kTransportSuccess) {
        INIT_ERROR("start http transport failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitCommand() {
    bool first_node = false;
    if (!conf_.Get("tenon", "first_node", first_node)) {
        INIT_ERROR("get conf tenon first_node failed!");
        return kInitError;
    }

    bool show_cmd = false;
    if (!conf_.Get("tenon", "show_cmd", show_cmd)) {
        INIT_ERROR("get conf tenon show_cmd failed!");
        return kInitError;
    }

    if (!cmd_.Init(first_node, show_cmd)) {
        INIT_ERROR("init command failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitNetworkSingleton() {
    if (network::Bootstrap::Instance()->Init(conf_) != network::kNetworkSuccess) {
        INIT_ERROR("init bootstrap failed!");
        return kInitError;
    }

    conf_.Set("tenon", "get_init_msg", dht::kBootstrapInit);
    if (network::UniversalManager::Instance()->CreateUniversalNetwork(
            conf_,
            transport_) != network::kNetworkSuccess) {
        INIT_ERROR("create universal network failed!");
        return kInitError;
    }

    conf_.Set("tenon", "get_init_msg", dht::kBootstrapNoInit);
    if (network::UniversalManager::Instance()->CreateNodeNetwork(
            conf_,
            transport_) != network::kNetworkSuccess) {
        INIT_ERROR("create node network failed!");
        return kInitError;
    }

    return kInitSuccess;
}

int NetworkInit::InitConfigWithArgs(int argc, char** argv) {
    common::ParserArgs parser_arg;
    if (ParseParams(argc, argv, parser_arg) != kInitSuccess) {
        INIT_ERROR("parse params failed!");
        return kInitError;
    }

    if (parser_arg.Has("h")) {
        cmd_.Help();
        exit(0);
    }

    if (parser_arg.Has("v")) {
        std::string version_info = common::GlobalInfo::Instance()->GetVersionInfo();
        exit(0);
    }

    parser_arg.Get("c", config_path_);
    if (config_path_.empty()) {
        config_path_ = kDefaultConfigPath;
    }

    if (!conf_.Init(config_path_.c_str())) {
        INIT_ERROR("init config file failed: %s", config_path_.c_str());
        return kInitError;
    }

    if (ResetConfig(parser_arg) != kInitSuccess) {
        INIT_ERROR("reset config with arg parser failed!");
        return kInitError;
    }

    return kInitSuccess;
}

void NetworkInit::StartMoreServer() {
#ifndef _WIN32
    bool use_rotation_port = false;
    if (!conf_.Get("tenon", "use_rotation_port", use_rotation_port) || !use_rotation_port) {
        INIT_ERROR("get conf tenon show_cmd failed!");
        return;
    }

    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    transport::TcpTransport* tcp_transport = dynamic_cast<transport::TcpTransport*>(
            tcp_transport_.get());
    for (int i = -1; i <= 1; ++i) {
        tcp_transport->CreateNewServer(
                "0.0.0.0",
                common::GlobalInfo::Instance()->id(),
                now_timestamp_days + i,
                common::kNodePortRangeMin,
                common::kNodePortRangeMax,
                started_port_set_);
    }

    tcp_transport->DestroyTailServer(common::kMaxRotationCount, started_port_set_);
#endif
}

int NetworkInit::ResetConfig(common::ParserArgs& parser_arg) {
        std::string db_path;
    if (parser_arg.Get("d", db_path) == common::kParseSuccess) {
        if (!conf_.Set("db", "path", db_path)) {
            INIT_ERROR("set config failed [db][path][%s]", db_path.c_str());
            return kInitError;
        }
    }
    std::string country;
    parser_arg.Get("o", country);
    if (!country.empty()) {
        if (!conf_.Set("tenon", "country", country)) {
            INIT_ERROR("set config failed [node][country][%s]", country.c_str());
            return kInitError;
        }
    }

    std::string tcp_spec;
    conf_.Get("tenon", "tcp_spec", tcp_spec);
    common::Split<> tcp_spec_split(tcp_spec.c_str(), ':', tcp_spec.size());
    std::string tcp_spec_ip = "0.0.0.0";
    std::string tcp_spec_port = "0";
    if (tcp_spec_split.Count() > 1) {
        tcp_spec_ip = tcp_spec_split[0];
        tcp_spec_port = tcp_spec_split[1];
    }

    std::string local_ip;
    parser_arg.Get("a", local_ip);
    if (!local_ip.empty()) {
        if (!conf_.Set("tenon", "local_ip", local_ip)) {
            INIT_ERROR("set config failed [node][local_ip][%s]", local_ip.c_str());
            return kInitError;
        }

        tcp_spec = local_ip + ":" + tcp_spec_port;
        tcp_spec_ip = local_ip;
    }

    uint16_t local_port = 0;
    if (parser_arg.Get("l", local_port) == common::kParseSuccess) {
        if (!conf_.Set("tenon", "local_port", local_port)) {
            INIT_ERROR("set config failed [node][local_port][%d]", local_port);
            return kInitError;
        }

        tcp_spec = tcp_spec_ip + ":" + std::to_string(local_port + 1);
    }

    if (!conf_.Set("tenon", "tcp_spec", tcp_spec)) {
        INIT_ERROR("set config failed [node][id][%s]", tcp_spec.c_str());
        return kInitError;
    }

    std::string prikey;
    parser_arg.Get("k", prikey);
    if (!prikey.empty()) {
        if (!conf_.Set("tenon", "prikey", prikey)) {
            INIT_ERROR("set config failed [node][id][%s]", prikey.c_str());
            return kInitError;
        }
    }

    int first = 0;
    if (parser_arg.Get("f", first) == common::kParseSuccess) {
        bool first_node = false;
        if (first == 1) {
            first_node = true;
        }

        if (!conf_.Set("tenon", "first_node", first_node)) {
            INIT_ERROR("set config failed [node][first_node][%d]", first_node);
            return kInitError;
        }
    }

    std::string network_ids;
    if (parser_arg.Get("n", network_ids) == common::kParseSuccess) {
        if (!conf_.Set("tenon", "net_ids", network_ids)) {
            INIT_ERROR("set config failed [node][net_id][%s]", network_ids.c_str());
            return kInitError;
        }
    }

    std::string peer;
    parser_arg.Get("p", peer);
    if (!peer.empty()) {
        if (!conf_.Set("tenon", "bootstrap", peer)) {
            INIT_ERROR("set config failed [node][bootstrap][%s]", peer.c_str());
            return kInitError;
        }
    }

    std::string id;
    parser_arg.Get("i", id);
    if (!id.empty()) {
        if (!conf_.Set("tenon", "id", id)) {
            INIT_ERROR("set config failed [node][id][%s]", peer.c_str());
            return kInitError;
        }
    }

    int show_cmd = 1;
    if (parser_arg.Get("g", show_cmd) == common::kParseSuccess) {
        if (!conf_.Set("tenon", "show_cmd", show_cmd == 1)) {
            INIT_ERROR("set config failed [node][show_cmd][%d]", show_cmd);
            return kInitError;
        }
    }

    int vpn_vip_level = 0;
    if (parser_arg.Get("V", vpn_vip_level) == common::kParseSuccess) {
        if (!conf_.Set("tenon", "vpn_vip_level", vpn_vip_level)) {
            INIT_ERROR("set config failed [node][vpn_vip_level][%d]", vpn_vip_level);
            return kInitError;
        }
    }

    std::string log_path;
    if (parser_arg.Get("L", log_path) != common::kParseSuccess) {
        log_path = "log/tenon.log";
    }

    if (!conf_.Set("log", "path", log_path)) {
        INIT_ERROR("set config failed [log][log_path][%s]", log_path.c_str());
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::ParseParams(int argc, char** argv, common::ParserArgs& parser_arg) {
    parser_arg.AddArgType('h', "help", common::kNoValue);
    parser_arg.AddArgType('g', "show_cmd", common::kMaybeValue);
    parser_arg.AddArgType('p', "peer", common::kMaybeValue);
    parser_arg.AddArgType('f', "first_node", common::kMaybeValue);
    parser_arg.AddArgType('l', "local_port", common::kMaybeValue);
    parser_arg.AddArgType('a', "local_ip", common::kMaybeValue);
    parser_arg.AddArgType('o', "country_code", common::kMaybeValue);
    parser_arg.AddArgType('k', "private_key", common::kMaybeValue);
    parser_arg.AddArgType('n', "network", common::kMaybeValue);
    parser_arg.AddArgType('c', "config_path", common::kMaybeValue);
    parser_arg.AddArgType('d', "db_path", common::kMaybeValue);
    parser_arg.AddArgType('v', "version", common::kNoValue);
    parser_arg.AddArgType('L', "log_path", common::kMaybeValue);
    parser_arg.AddArgType('i', "id", common::kMaybeValue);
    parser_arg.AddArgType('V', "vpn_vip_level", common::kNoValue);
    parser_arg.AddArgType('U', "gen_root", common::kNoValue);
    parser_arg.AddArgType('S', "gen_shard", common::kNoValue);
    parser_arg.AddArgType('1', "root_nodes", common::kMaybeValue);
    parser_arg.AddArgType('2', "shard_nodes", common::kMaybeValue);

    std::string tmp_params = "";
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) == 0) {
            tmp_params += static_cast<char>(31);
        }
        else {
            tmp_params += argv[i];
        }
        tmp_params += " ";
    }

    std::string err_pos;
    if (parser_arg.Parse(tmp_params, err_pos) != common::kParseSuccess) {
        INIT_ERROR("parse params failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::SetPriAndPubKey(const std::string&) {
    std::string prikey("");
    conf_.Get("tenon", "prikey", prikey);
    prikey = common::Encode::HexDecode(prikey);
    std::shared_ptr<security::PrivateKey> prikey_ptr{ nullptr };
    if (!prikey.empty()) {
        security::PrivateKey tmp_prikey(prikey);
        prikey_ptr = std::make_shared<security::PrivateKey>(tmp_prikey);
    } else {
        security::PrivateKey tmp_prikey;
        prikey_ptr = std::make_shared<security::PrivateKey>(tmp_prikey);
        prikey_ptr->Serialize(prikey);
        if (prikey.empty()) {
            return kInitError;
        }
    }

    security::Security::Instance()->set_prikey(prikey_ptr);
    std::string account_id = security::Secp256k1::Instance()->ToAddressWithPrivateKey(prikey);
    std::string account_id_with_pubkey = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Security::Instance()->str_pubkey());
    common::GlobalInfo::Instance()->set_id(account_id);
    conf_.Set("tenon", "prikey", common::Encode::HexEncode(
        security::Security::Instance()->str_prikey()));
    conf_.Set("tenon", "pubkey", common::Encode::HexEncode(
        security::Security::Instance()->str_pubkey()));
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Security::Instance()->str_pubkey_uncompress());
    common::GlobalInfo::Instance()->set_id(account_address);
    conf_.Set("tenon", "id", common::Encode::HexEncode(
        common::GlobalInfo::Instance()->id()));
    conf_.DumpConfig(config_path_);
    return kInitSuccess;
}

int NetworkInit::InitBlock(const common::Config& conf) {
    std::string db_path;
    conf.Get("db", "path", db_path);
    auto st = db::Db::Instance()->Init(db_path);
    if (!st) {
        INIT_ERROR("init db[%s] failed!", db_path.c_str());
        return kInitError;
    }

    common::Config tmp_conf = conf;
    if (block::BlockManager::Instance()->Init(tmp_conf) != block::kBlockSuccess) {
        INIT_ERROR("init block manager failed!");
        return kInitError;
    }

    return kInitSuccess;
}

}  // namespace init

}  // namespace tenon
