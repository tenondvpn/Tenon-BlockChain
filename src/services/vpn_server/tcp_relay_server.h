#pragma once

#include <vector>
#include <deque>
#include <unordered_map>

#include "common/utils.h"
#include "common/tick.h"
#include "common/thread_safe_queue.h"
#include "transport/tcp/tcp_transport.h"
#include "transport//processor.h"
#include "transport/proto/transport.pb.h"
#include "tnet/tcp_acceptor.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace tenon {

namespace vpn {

class TcpRelayServer {
public:
    TcpRelayServer(transport::TransportPtr tcp_transport)
            : tcp_transport_(tcp_transport) {
    }

    int Init(const std::string& ip, uint16_t port) {
        transport::TcpTransport* tcp_transport = dynamic_cast<transport::TcpTransport*>(
                tcp_transport_.get());
#ifndef CLIENT_USE_UV
        tcp_acceptor_ = tcp_transport->CreateNewServer(ip, port);
#endif
        if (tcp_acceptor_ == nullptr) {
            return kVpnsvrError;
        }

        return kVpnsvrSuccess;
    }

private:
    transport::TransportPtr tcp_transport_{ nullptr };
    tnet::TcpAcceptor* tcp_acceptor_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(TcpRelayServer);
};

typedef std::shared_ptr<TcpRelayServer> TcpRelayServerPtr;

class TcpRelayServerManager {
public:
    static TcpRelayServerManager* Instance();
    int Init(
            transport::TransportPtr& tcp_transport,
            const std::string& dht_key,
            const std::string&ip,
            uint16_t min_port,
            uint16_t max_port);
    VlanNodeInfoPtr IsVlanNode(const std::string& ip, uint16_t port);
    std::unordered_map<std::string, VlanNodeInfoPtr> vlan_node_map() {
        std::lock_guard<std::mutex> guard(client_map_mutex_);
        return client_map_;
    }

private:
    TcpRelayServerManager() {}

    ~TcpRelayServerManager() {}

    void HandleMessage(std::shared_ptr<tnet::TcpConnection>& conn, char* msg, uint32_t len);
    void RotationCreateServer();
    int Handshake(std::shared_ptr<tnet::TcpConnection>& tcp_conn);
    int VlanNodeHeartbeatDetail(
        std::shared_ptr<tnet::TcpConnection>& conn,
            char* msg,
            uint32_t len);
    void Rotation() {
        RotationCreateServer();
        rotation_server_tick_.CutOff(
                kRotationTimePeriod,
                std::bind(&TcpRelayServerManager::Rotation, this));
    }

    static const uint64_t kRotationTimePeriod = 3600lu * 1000000lu;

    uint32_t relay_server_idx_{ 0 };
    std::map<uint32_t, TcpRelayServerPtr> tcp_servers_;
    std::mutex tcp_servers_mutex_;
    std::string ip_;
    uint16_t min_port_{ 0 };
    uint16_t max_port_{ 0 };
    std::string dht_key_;
    transport::TransportPtr tcp_transport_{ nullptr };
    std::deque<uint16_t> valid_port_;
    uint32_t client_idx_{ 0 };
    std::unordered_map<std::string, VlanNodeInfoPtr> client_map_;
    std::mutex client_map_mutex_;
    common::Tick rotation_server_tick_;
    
    DISALLOW_COPY_AND_ASSIGN(TcpRelayServerManager);
};

}  // namespace vpn

}  // namespace tenon
