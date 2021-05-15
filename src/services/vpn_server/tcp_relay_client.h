#pragma once

#include <vector>
#include <deque>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif

#include "ssr/crypto.h"

#ifdef __cplusplus
}
#endif

#include "common/utils.h"
#include "common/tick.h"
#include "transport/tcp/tcp_transport.h"
#include "transport//processor.h"
#include "transport/proto/transport.pb.h"
#include "tnet/tcp_acceptor.h"
#include "services/vpn_server/vpn_svr_utils.h"
#include "services/vpn_server/vpn_server.h"

namespace lego {

namespace vpn {

struct RouteServer {
    std::string dht_key;
    std::string ip;
    uint16_t min_port;
    uint16_t max_port;
    uint16_t min_stream_port;
    uint16_t max_stream_port;
    uint32_t local_ip_int;
    uint16_t local_port;
};

struct InItem {
    buffer_t* new_buf;
    VlanConnection* conn;
};

typedef int(*RelayClientRecvCallback)(
        uint32_t server_id,
        uint32_t stream_id,
        char* data,
        uint32_t len);

class TcpRelayClientManager {
public:
    static TcpRelayClientManager* Instance();
    void Init(transport::TransportPtr& tcp_transport, RelayClientRecvCallback recv_callback) {
//         auto tcp_trans = dynamic_cast<transport::TcpTransport*>(tcp_transport_.get());
//         tcp_trans->SetRawCallback(std::bind(
//                 &TcpRelayClientManager::HandleMessage,
//                 this,
//                 std::placeholders::_1,
//                 std::placeholders::_2,
//                 std::placeholders::_3));
        recv_callback_ = recv_callback;
//         RotationConnectServer();
//         RotationConnectStreamServer();
    }
    int AddNewRouteServer(
            const std::string& dht_key,
            const std::string&ip,
            uint16_t min_port,
            uint16_t max_port);
    VlanConnection* GetStreamConn(uint32_t client_id);
    void EraseStreamConn(VlanConnection* tcp_con);
    int SendStreamPacket(
            uint32_t stream_id,
            uint32_t server_id,
            const char* data,
            uint32_t len,
            remote_t* real_remote);
    int SendStopServer(uint32_t client_id, uint32_t server_id);
    void HandleMessage(VlanConnection* conn, char* msg, uint32_t len);
    void RemoveVlanRemote(VlanConnection* vlan_conn);
    void ResetRemoteStatus(uint64_t key, int32_t status) {
        remote_status_map_[key] = status;
    }

private:
    TcpRelayClientManager() {}

    ~TcpRelayClientManager() {}

    void RotationConnectServer();
    void RotationConnectStreamServer();
    int Handshake(VlanConnection* tcp_conn);
    int HandshakeDetail(VlanConnection* tcp_conn);
    VlanConnection* CreateAndHandshake(
            uint32_t timestamp_day,
            const RouteServer& route_svr);
    VlanConnection* ConnectStreamServer(
            uint32_t client_id,
            const RouteServer& route_svr);
    int StreamHandshake(
            uint32_t client_id,
            VlanConnection* tcp_conn,
            const RouteServer& route_svr);
    int HandleVlanMessage(TnetWithRelayHead* tnet_header, VlanConnection* conn);

    static const uint64_t kRotationPeriod = 600lu * 1000000lu;
    static const uint64_t kStreamRotationPeriod = 1lu * 1000000lu;
    
    std::unordered_map<uint32_t, RouteServer> conn_map_;
    std::mutex conn_map_mutex_;
    std::unordered_map<VlanConnection*, RouteServer> tmp_conn_map_;
    std::mutex tmp_conn_map_mutex_;
    std::unordered_map<uint32_t, std::deque<VlanConnection*>> stream_conn_map_;
    std::mutex stream_conn_map_mutex_;
    std::unordered_map<uint32_t, VlanConnection*> saved_stream_conn_map_;
    std::mutex saved_stream_conn_map_mutex_;
    common::Tick rotation_tick_;
    RelayClientRecvCallback recv_callback_{ nullptr };
    std::unordered_map<uint64_t, int32_t> remote_status_map_;
    std::deque<InItem> in_buffer_queue_;
    uint32_t client_id_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(TcpRelayClientManager);
};

}  // namespace vpn

}  // namespace lego
