#pragma once

#include <thread>
#include <memory>
#include <unordered_map>
#include <queue>
#include <mutex>

#include "common/tick.h"
#include "common/thread_safe_queue.h"
#include "block/proto/block.pb.h"
#include "contract/proto/contract.pb.h"
#include "transport/proto/transport.pb.h"
#include "services/vpn_server/vpn_svr_utils.h"
#include "services/vpn_server/server.h"
#include "services/vpn_server/messge_window.h"
#include "transport/udp/udp_transport.h"
#include "transport/udp/ev_udp_transport.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace vpn {

class VpnServer {
public:
    static VpnServer* Instance();
    int Init(uint16_t min_port, uint16_t max_port);
    int ParserReceivePacket(const char* buf);
    void Stop();

    common::ThreadSafeQueue<StakingItemPtr>& staking_queue() {
        return staking_queue_;
    }

    common::ThreadSafeQueue<BandwidthInfoPtr>& bandwidth_queue() {
        return bandwidth_queue_;
    }

    std::shared_ptr<listen_ctx_t> last_listen_ptr() {
        return last_listen_ptr_;
    }

    bool VipCommitteeAccountValid(const std::string& to) {
        auto iter = vip_committee_accounts_.find(to);
        return iter != vip_committee_accounts_.end();
    }

    bool ClientAccountValid(const std::string& to) {
        auto iter = valid_client_account_.find(to);
        return iter != valid_client_account_.end();
    }

    void SendGetAccountAttrLastBlock(
            const std::string& attr,
            const std::string& account,
            uint64_t height);
    std::unordered_map<std::string, BandwidthInfoPtr>& account_bindwidth_map() {
        return account_bindwidth_map_;
    }

    int SendStreamData(server_t* server);
    void SendStopServer(uint32_t server_id);
    void HandleHeartbeatResponse(
            user_ev_io_t* user_ev_io,
            transport::TransportHeader* trans_header,
            const struct sockaddr* addr);
    vpn::UdpUserData* GetUdpUserData(const struct sockaddr* addr);
    user_ev_io_t* GetEvUserIo();
    uint16_t GetRoutePort(const std::string& ip);

private:
    struct RemoteInfo {
        uint16_t min_port;
        uint16_t max_port;
        std::string dht_key;
    };

    VpnServer();
    ~VpnServer();
    void CheckTransactions();
    void CheckAccountValid();

    void HandleMessage(transport::protobuf::Header& header);
    void HandleVpnLoginResponse(
            transport::protobuf::Header& header,
            block::protobuf::BlockMessage& block_msg);
    void HandleClientBandwidthResponse(
            transport::protobuf::Header& header,
            contract::protobuf::ContractMessage& contract_msg);
    void RotationServer();
    void StartMoreServer();
    void StartMoreUdpServer();
    void CheckVersion();
    void SendGetAccountAttrUsedBandwidth(const std::string& account);
    void ChooseRelayRouteNodes();
    void RoutingNodesHeartbeat();

    inline uint16_t GetVpnPort(const std::string& dht_key, uint32_t timestamp_days) {
        std::string tmp_str = dht_key + std::to_string(timestamp_days);
        uint32_t hash32 = common::Hash::Hash32(tmp_str);
        uint32_t vpn_route_range = vpn_max_port_ - vpn_min_port_;
        uint16_t tmp_port = (hash32 % vpn_route_range) + vpn_min_port_;
        return tmp_port;
    }

    std::unordered_set<std::string> valid_addr_set_;
    std::mutex valid_addr_set_mutex_;

    static const uint32_t kStakingCheckingPeriod = 10 * 1000 * 1000;
    static const uint32_t kAccountCheckPeriod = 10 * 1000 * 1000;
    static const uint32_t kConnectInitBandwidth = 5 * 1024 * 1024;
    static const uint32_t kAddBandwidth = 200u * 1024u * 1024u;
    static const uint32_t kMaxRelayRouteNode = 32u;
    static const int64_t kRoutingNodeHeartbeatPeriod = 3ll * 1000ll * 1000ll;

    common::ThreadSafeQueue<StakingItemPtr> staking_queue_;
    common::ThreadSafeQueue<BandwidthInfoPtr> bandwidth_queue_;
    common::Tick staking_tick_;
    common::Tick bandwidth_tick_;
    common::Tick check_ver_tick_;
    common::Tick routing_nodes_hb_tick_;
    std::unordered_map<std::string, StakingItemPtr> gid_map_;
    std::unordered_map<std::string, BandwidthInfoPtr> account_map_;
    std::mutex account_map_mutex_;
    std::deque<std::shared_ptr<listen_ctx_t>> listen_ctx_queue_;
    common::Tick new_vpn_server_tick_;
    std::shared_ptr<listen_ctx_t> last_listen_ptr_{ nullptr };
    std::set<uint16_t> started_port_set_;
    std::set<std::string> vip_committee_accounts_;
    std::unordered_set<std::string> valid_client_account_;
    std::mutex valid_client_account_mutex_;
    std::string admin_vpn_account_;
    uint64_t vpn_version_last_height_{ 0 };
    uint16_t vpn_min_port_{ 0 };
    uint16_t vpn_max_port_{ 0 };
    std::deque<uv_udp_t*> udp_queue_;

    // just vpn server, thread safe
    std::unordered_map<std::string, BandwidthInfoPtr> account_bindwidth_map_;
    std::vector<init::VpnServerNodePtr> routing_nodes_;
    std::vector<int> routing_pos_vec_;
    uint16_t last_port_{ 0 };
    transport::EvUdpTransport ev_udp_transport_;
    std::deque<user_ev_io_t*> ev_udp_queue_;
    std::unordered_map<std::string, vpn::UdpUserData*> udp_user_data_map_;
    uint32_t valid_ev_io_idx_{ 0 };
    std::map<std::string, RemoteInfo> remote_ip_dhtkey_map_;
    int32_t valid_ev_port_idx_{ -10 };

    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

}  // namespace vpn

}  // namespace tenon
