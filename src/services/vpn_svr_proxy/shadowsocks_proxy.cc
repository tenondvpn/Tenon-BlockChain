#include "stdafx.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/user_property_key_define.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "ip/ip_with_country.h"
#include "security/ecdh_create_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "init/update_vpn_init.h"
#include "sync/key_value_sync.h"
#include "services/vpn_server/vpn_server.h"
#include "services/vpn_svr_proxy/proxy_utils.h"
#include "services/vpn_route/route_tcp.h"
#include "services/vpn_server/vpn_route.h"

namespace tenon {

namespace vpn {

ShadowsocksProxy::ShadowsocksProxy() {
//     tick_status_.CutOff(
//             kCheckVpnServerStatusPeriod,
//             std::bind(&ShadowsocksProxy::CheckVpnStatus, this));
}

ShadowsocksProxy::~ShadowsocksProxy() {}

void ShadowsocksProxy::Destroy() {
    transport_->Stop();
    vpn::VpnServer::Instance()->Stop();
    network::DhtManager::Instance()->Destroy();
}

void ShadowsocksProxy::HandleMessage(transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    if (header.type() != common::kServiceMessage) {
        return;
    }

    auto dht = network::Route::Instance()->GetDht(header.des_dht_key(), header.universal());
    assert(dht);
    dht->HandleMessage(header);
}

ShadowsocksProxy* ShadowsocksProxy::Instance() {
    static ShadowsocksProxy ins;
    return &ins;
}

int ShadowsocksProxy::Init(int argc, char** argv) {
    network::Route::Instance()->RegisterMessage(
        common::kServiceMessage,
        std::bind(&ShadowsocksProxy::HandleMessage, this, std::placeholders::_1));

    std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        PROXY_ERROR("network inited!");
        return kProxyError;
    }

    if (InitConfigWithArgs(argc, argv) != kProxySuccess) {
        PROXY_ERROR("init config with args failed!");
        return kProxyError;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        PROXY_ERROR("init ip config with args failed!");
        return kProxyError;
    }

    if (!db::Db::Instance()->Init("./vdb")) {
        PROXY_ERROR("init db failed!");
        return kProxyError;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        PROXY_ERROR("init global info failed!");
        return kProxyError;
    }

    if (SetPriAndPubKey("") != kProxySuccess) {
        PROXY_ERROR("set node private and public key failed!");
        return kProxyError;
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        PROXY_ERROR("init ecdh create secret key failed!");
        return kProxyError;
    }

    network::UniversalManager::Instance();
    network::Route::Instance();
    network::DhtManager::Instance();
//     if (InitUdpTransport() != kProxySuccess) {
//         PROXY_ERROR("init transport failed!");
//         return kProxyError;
//     }

    if (InitTcpTransport() != kProxySuccess) {
        PROXY_ERROR("init tcp transport failed!");
        return kProxyError;
    }

    transport::MultiThreadHandler::Instance()->Init(
            transport_,
            tcp_transport_);
    if (InitHttpTransport() != transport::kTransportSuccess) {
        PROXY_ERROR("init http transport failed!");
        return kProxyError;
    }

    PROXY_ERROR("begin init network.");
    if (InitNetworkSingleton() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    PROXY_ERROR("success init network. "
        "min_r_port: %d, max_r_port: %d, min_s_port: %d, max_s_port: %d",
        common::GlobalInfo::Instance()->min_route_port(),
        common::GlobalInfo::Instance()->max_route_port(),
        common::GlobalInfo::Instance()->min_svr_port(),
        common::GlobalInfo::Instance()->max_svr_port());

    conf_.Get("tenon", "vpn_route_port", vpn_route_port_);
    uint32_t vpn_vip_level = 0;
    conf_.Get("tenon", "vpn_vip_level", vpn_vip_level);
    PROXY_ERROR("begin init InitTcpRelay.");
    if (InitTcpRelay(vpn_vip_level) != kProxySuccess) {
        PROXY_ERROR("init tcp relay failed!");
        return kProxyError;
    }

    PROXY_ERROR("success init InitTcpRelay.");
    conf_.Get("tenon", "vpn_server_port", vpn_server_port_);
    if (StartShadowsocks() != kProxySuccess) {
        PROXY_ERROR("start shadowsocks failed!");
        return kProxyError;
    }

    PROXY_ERROR("begin init ServerInit.");
    init::UpdateVpnInit::Instance()->ServerInit(conf_);
    for (int i = 0; i < 7; ++i) {
        if (init::UpdateVpnInit::Instance()->InitSuccess()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::microseconds(1000 * 1000));
    }

    PROXY_ERROR("success init ServerInit.");
    if (InitCommand() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    std::string gid;
    std::map<std::string, std::string> attrs;
    tenon::client::TransactionClient::Instance()->Transaction(
            "",
            0,
            "",
            attrs,
            common::kConsensusCreateAcount,
            gid);
    // check account address valid
    if (!init::UpdateVpnInit::Instance()->InitSuccess() &&
            !common::GlobalInfo::Instance()->config_first_node()) {
        PROXY_ERROR("init::UpdateVpnInit::Instance()->InitSuccess failed!");
    //    return kProxyError;
    }

    inited_ = true;
    cmd_.Run();
    transport_->Stop();
    vpn::VpnServer::Instance()->Stop();
    network::DhtManager::Instance()->Destroy();
    exit(0);
    return kProxySuccess;
}

int ShadowsocksProxy::InitTcpRelay(uint32_t vip_level) {
    if (vpn_route_port_ == 0) {
        return kProxySuccess;
    }

    uint32_t route_network_id = network::kVpnRouteNetworkId;
    switch (vip_level) {
        case 1:
            route_network_id = network::kVpnRouteVipLevel1NetworkId;
            break;
        case 2:
            route_network_id = network::kVpnRouteVipLevel2NetworkId;
            break;
        case 3:
            route_network_id = network::kVpnRouteVipLevel3NetworkId;
            break;
        case 4:
            route_network_id = network::kVpnRouteVipLevel4NetworkId;
            break;
        case 5:
            route_network_id = network::kVpnRouteVipLevel5NetworkId;
            break;
        default:
            break;
    }

    vpn_route_ = std::make_shared<VpnProxyNode>(
        route_network_id,
        std::bind(
            &elect::ElectManager::GetMemberWithId,
            elect::ElectManager::Instance(),
            std::placeholders::_1,
            std::placeholders::_2));
    int res = vpn_route_->Init();
    if (res != dht::kDhtSuccess) {
        vpn_route_ = nullptr;
        PROXY_ERROR("node join network [%u] [%d] failed!", route_network_id, res);
        return kProxyError;
    }

    uint16_t route_min_port = common::GlobalInfo::Instance()->min_route_port();
    uint16_t route_max_port = common::GlobalInfo::Instance()->max_route_port();
    res = vpn::VpnRoute::Instance()->Init(vip_level, route_min_port, route_max_port);
    if (res != vpnroute::kVpnRouteSuccess) {
        return kProxyError;
    }

    return kProxySuccess;
}

void ShadowsocksProxy::GetShadowsocks(uint16_t& route_port, uint16_t& vpn_port) {
    route_port = vpn_route_port_;
    auto last_ptr = vpn::VpnServer::Instance()->last_listen_ptr();
    if (last_ptr != nullptr) {
        vpn_port = last_ptr->vpn_port;
    }
}

int ShadowsocksProxy::StartShadowsocks() {
    if (vpn_server_port_ == 0) {
        return kProxySuccess;
    }

    vpn_proxy_ = std::make_shared<VpnProxyNode>(
        network::kVpnNetworkId,
        std::bind(
            &elect::ElectManager::GetMemberWithId,
            elect::ElectManager::Instance(),
            std::placeholders::_1,
            std::placeholders::_2));
    if (vpn_proxy_->Init() != network::kNetworkSuccess) {
        vpn_proxy_ = nullptr;
        PROXY_ERROR("node join network [%u] failed!", network::kVpnNetworkId);
        return kProxyError;
    }

    uint16_t vpn_min_port = common::GlobalInfo::Instance()->min_svr_port();
    uint16_t vpn_max_port = common::GlobalInfo::Instance()->max_svr_port();
    if (VpnServer::Instance()->Init(vpn_min_port, vpn_max_port) != kVpnsvrSuccess) {
        return kProxyError;
    }

    return kProxySuccess;
}

}  // namespace vpn

}  // namespace tenon
