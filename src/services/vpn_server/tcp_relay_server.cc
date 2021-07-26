#include "services/vpn_server/tcp_relay_server.h"

#include "common/time_utils.h"
#include "services/proto/service_proto.h"
#include "transport/tcp/msg_packet.h"
#include "transport/tcp/tcp_transport.h"

namespace tenon {

namespace vpn {

TcpRelayServerManager* TcpRelayServerManager::Instance() {
    static TcpRelayServerManager ins;
    return &ins;
}

int TcpRelayServerManager::Init(
        transport::TransportPtr& tcp_transport,
        const std::string& dht_key,
        const std::string&ip,
        uint16_t min_port,
        uint16_t max_port) {
    dht_key_ = dht_key;
    ip_ = ip;
    min_port_ = min_port;
    max_port_ = max_port;
    tcp_transport_ = tcp_transport;
    auto tcp_ptr = dynamic_cast<transport::TcpTransport*>(tcp_transport_.get());
    tcp_ptr->SetRawCallback(std::bind(
            &TcpRelayServerManager::HandleMessage,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3));
    Rotation();
    return kVpnsvrSuccess;
}

int TcpRelayServerManager::Handshake(std::shared_ptr<tnet::TcpConnection>& tcp_conn) {
    transport::MsgPacket* reply_packet = new transport::MsgPacket(
            tnet::kRaw, tnet::kEncodeWithHeader, false);
    std::string msg(sizeof(TcpRelayHead) + 6, 0);
    TcpRelayHead* head = (TcpRelayHead*)(msg.data());
    head->client_id = tcp_conn->id();
    head->server_id = 0;
    std::string from_ip;
    uint16_t from_port;
    tcp_conn->GetSocket()->GetIpPort(&from_ip, &from_port);
    struct in_addr s;
    inet_pton(AF_INET, from_ip.c_str(), &s);
    uint32_t* int_ip = (uint32_t*)(head + 1);
    *int_ip = s.s_addr;
    uint16_t* int_port = (uint16_t*)(int_ip + 1);
    *int_port = from_port;
    reply_packet->SetMessage(&msg);
    if (!tcp_conn->SendPacket(*reply_packet)) {
        reply_packet->Free();
        tcp_transport_->FreeConnection(tcp_conn->ip(), tcp_conn->port());
        return kVpnsvrError;
    }

    return kVpnsvrSuccess;
}

void TcpRelayServerManager::HandleMessage(
        std::shared_ptr<tnet::TcpConnection>& conn,
        char* data,
        uint32_t len) {
    if (data == nullptr) {
        // free connection
        return;
    }

    TcpRelayHead* relay_head = (TcpRelayHead*)data;
    if (conn->id() == 0) {
        conn->set_id(relay_head->client_id);
        if (relay_head->server_id == 1) {
            Handshake(conn);
            conn->set_id(0);
            return;
        }

        VlanNodeHeartbeatDetail(conn, data, len);
    }
}

int TcpRelayServerManager::VlanNodeHeartbeatDetail(
        std::shared_ptr<tnet::TcpConnection>& conn,
        char* data,
        uint32_t len) {
    service::protobuf::VlanNodeHeartbeat vlan_hb;
    std::string req_str(
            data + sizeof(TcpRelayHead),
            len - sizeof(TcpRelayHead));
    if (!vlan_hb.ParseFromString(req_str)) {
        return kVpnsvrError;
    }

    std::string from_ip;
    uint16_t from_port;
    conn->GetSocket()->GetIpPort(&from_ip, &from_port);
    std::string key = std::string(from_ip) + "_" + std::to_string(from_port);
    std::cout << "vlan node coming: " << key << std::endl;
    TcpRelayHead* relay_head = (TcpRelayHead*)data;
    std::lock_guard<std::mutex> guard(client_map_mutex_);
    auto iter = client_map_.find(key);
    if (iter == client_map_.end()) {
        conn->set_id(relay_head->client_id);
        auto new_node = std::make_shared<VlanNodeInfo>(
                from_ip,
                from_port,
                vlan_hb.dht_key(),
                vlan_hb.public_key(),
                0);
        client_map_[key] = new_node;
    } else {
        iter->second->dht_key = vlan_hb.dht_key();
        iter->second->public_key = vlan_hb.public_key();
        iter->second->timeout_times = 0;
    }

    return kVpnsvrSuccess;
}

void TcpRelayServerManager::RotationCreateServer() {
    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    std::vector<uint16_t> tmp_ports;
    for (int i = -1; i <= 1; ++i) {
        auto port = common::GetVpnServerPort(
                dht_key_,
                now_timestamp_days + i,
                min_port_,
                max_port_);
        if (std::find(valid_port_.begin(), valid_port_.end(), port) != valid_port_.end()){
            continue;
        }

        if (std::find(tmp_ports.begin(), tmp_ports.end(), port) != tmp_ports.end()) {
            continue;
        }

        tmp_ports.push_back(port);
    }

    if (tmp_ports.empty()) {
        return;
    }

    for (uint32_t i = 0; i < tmp_ports.size(); ++i) {
        auto tcp_relay_server = std::make_shared<TcpRelayServer>(tcp_transport_);
        if (tcp_relay_server->Init(ip_, tmp_ports[i]) != kVpnsvrSuccess) {
            continue;
        }

        {
            std::lock_guard<std::mutex> guard(tcp_servers_mutex_);
            tcp_servers_[tmp_ports[i]] = tcp_relay_server;
        }

        valid_port_.push_back(tmp_ports[i]);
    }

    if (valid_port_.size() >= common::kMaxRotationCount) {
        {
            std::lock_guard<std::mutex> guard(tcp_servers_mutex_);
            tcp_servers_.erase(valid_port_.front());
        }

        valid_port_.pop_front();
    }
}

VlanNodeInfoPtr TcpRelayServerManager::IsVlanNode(
        const std::string& ip,
        uint16_t port) {
    std::lock_guard<std::mutex> guard(client_map_mutex_);
    std::string key = ip + "_" + std::to_string(port);
    auto iter = client_map_.find(key);
    if (iter != client_map_.end()) {
        return iter->second;
    }

    return nullptr;
}

}  // namespace vpn

}  // namespace tenon
