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
#include "services/bandwidth_manager.h"
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

    common::ThreadSafeQueue<service::BandwidthInfoPtr>& bandwidth_queue() {
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
    std::unordered_map<std::string, service::BandwidthInfoPtr>& account_bindwidth_map() {
        return account_bindwidth_map_;
    }

    int SendStreamData(server_t* server, remote_t* remote);
    void HandleHeartbeatResponse(
            user_ev_io_t* user_ev_io,
            transport::TransportHeader* trans_header,
            const struct sockaddr* addr);
    vpn::UdpUserData* GetUdpUserData(const struct sockaddr* addr);
    user_ev_io_t* GetEvUserIo();
    uint16_t GetRoutePort(const std::string& ip);
    std::string GetVpnCount(const std::string& uid);

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

    void HandleMessage(transport::TransportMessagePtr& header);
    void HandleVpnLoginResponse(
            transport::protobuf::Header& header,
            block::protobuf::BlockMessage& block_msg);
    void HandleClientBandwidthResponse(
            transport::protobuf::Header& header,
            contract::protobuf::ContractMessage& contract_msg);
    void RotationServer();
    void StartMoreServer();
    void CheckVersion();
    void SendGetAccountAttrUsedBandwidth(const std::string& account);
    void ChooseRelayRouteNodes();
    void RoutingNodesHeartbeat();
    void HandleUpdateVpnCountRequest(
            transport::protobuf::Header& header,
            block::protobuf::BlockMessage& block_msg);
    void HandleUpdateVpnActiveRequest(
            transport::protobuf::Header& header,
            block::protobuf::BlockMessage& block_msg);
    void CheckVpnNodeTimeout();
    void SaveAccountInitBlocks(transport::protobuf::Header& header);

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
    static const uint32_t kCheckNodeTimeout = 10000000u;

    common::ThreadSafeQueue<StakingItemPtr> staking_queue_;
    common::ThreadSafeQueue<service::BandwidthInfoPtr> bandwidth_queue_;
    common::Tick staking_tick_;
    common::Tick bandwidth_tick_;
    common::Tick check_ver_tick_;
    common::Tick routing_nodes_hb_tick_;
    std::unordered_map<std::string, StakingItemPtr> gid_map_;
    std::unordered_map<std::string, service::BandwidthInfoPtr> account_map_;
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
    std::unordered_map<std::string, service::BandwidthInfoPtr> account_bindwidth_map_;
    std::vector<init::VpnServerNodePtr> routing_nodes_;
    std::vector<int> routing_pos_vec_;
    uint16_t last_port_{ 0 };
    transport::EvUdpTransport ev_udp_transport_;
    std::deque<user_ev_io_t*> ev_udp_queue_;
    std::unordered_map<std::string, vpn::UdpUserData*> udp_user_data_map_;
    uint32_t valid_ev_io_idx_{ 0 };
    std::map<std::string, RemoteInfo> remote_ip_dhtkey_map_;
    int32_t valid_ev_port_idx_{ -10 };
    std::unordered_map<
            std::string,
            std::map<uint64_t, std::chrono::steady_clock::time_point>> vpn_node_used_count_map_;
    std::mutex vpn_node_used_count_map_mutex_;
    common::Tick vpn_node_count_tick_;

    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

class VlanConnection {
public:
    VlanConnection() {}
    ~VlanConnection();

    int Connect(const std::string& ip, uint16_t port);
    bool SendPacket(const char* data, uint32_t len, remote_t* real_remote);
    int32_t SendLocalDataToRoute(remote_t* real_remote);

    uint32_t id() {
        return id_;
    }

    void set_id(uint32_t id) {
        id_ = id;
        remote_->id = id;
    }

    void set_data(const char* data, uint32_t len) {
        memcpy(data_buf_ + data_len_, data, len);
        data_len_ += len;
    }

    void shift_data(const char* new_start, uint32_t shift_len) {
        if (data_buf_ == new_start || shift_len == 0) {
            data_len_ = shift_len;
            return;
        }

        memmove(data_buf_, new_start, shift_len);
        data_len_ = shift_len;
    }

    uint32_t get_data_len() {
        return data_len_;
    }

    char* get_data_buf() {
        return data_buf_;
    }

// private:
    uint32_t id_{ 0 };
    remote_t* remote_{ NULL };
    char data_buf_[SOCKET_BUF_SIZE * 2 + 1024];
    uint32_t data_len_{ 0 };
};

}  // namespace vpn

}  // namespace tenon
