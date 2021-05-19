#include "services/vpn_server/tcp_relay_client.h"

#include "common/time_utils.h"
#include "common/header_type.h"
#include "security/schnorr.h"
#include "services/proto/service_proto.h"

namespace tenon {

namespace vpn {

TcpRelayClientManager* TcpRelayClientManager::Instance() {
    static TcpRelayClientManager ins;
    return &ins;
}

int TcpRelayClientManager::AddNewRouteServer(
        const std::string& dht_key,
        const std::string&ip,
        uint16_t min_port,
        uint16_t max_port) {
    RouteServer route_svr;
    route_svr.dht_key = dht_key;
    route_svr.ip = ip;
    route_svr.min_port = min_port;
    route_svr.max_port = max_port;
    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    auto tcp_conn = CreateAndHandshake(now_timestamp_days, route_svr);
    if (tcp_conn == nullptr) {
        return kVpnsvrError;
    }

    std::lock_guard<std::mutex> guard(tmp_conn_map_mutex_);
    tmp_conn_map_[tcp_conn] = route_svr;
    return kVpnsvrSuccess;
}

int TcpRelayClientManager::Handshake(VlanConnection* tcp_conn) {
    char msg[1024];
    transport::PacketHeader* pkg_header = (transport::PacketHeader*)msg;
    pkg_header->length = sizeof(TcpRelayHead);
    pkg_header->magic = transport::kTcpPacketMagicNumber;
    pkg_header->type = tnet::kRaw;

    TcpRelayHead* head = (TcpRelayHead*)(msg + sizeof(transport::PacketHeader));
    head->client_id = ++client_id_;
    head->server_id = 1;
    if (!tcp_conn->SendPacket(msg, sizeof(TcpRelayHead) + pkg_header->length, NULL)) {
        return kVpnsvrError;
    }

    return kVpnsvrSuccess;
}

int TcpRelayClientManager::HandshakeDetail(VlanConnection* tcp_conn) {
    char msg[1024];
    transport::PacketHeader* pkg_header = (transport::PacketHeader*)msg;
    pkg_header->magic = transport::kTcpPacketMagicNumber;
    pkg_header->type = tnet::kRaw;

    service::protobuf::VlanNodeHeartbeat vlan_hb;
    vlan_hb.set_public_key(security::Schnorr::Instance()->str_pubkey());
    std::string res_str = vlan_hb.SerializeAsString();
    pkg_header->length = sizeof(TcpRelayHead) + res_str.size();
    TcpRelayHead* head = (TcpRelayHead*)(msg + sizeof(transport::PacketHeader));
    head->client_id = tcp_conn->id();
    head->server_id = 0;
    memcpy((char*)(head + 1), res_str.c_str(), res_str.size());
    if (!tcp_conn->SendPacket(msg, pkg_header->length + sizeof(transport::PacketHeader), NULL)) {
        return kVpnsvrError;
    }

    std::cout << "sent detail." << std::endl;
    RouteServer route_server;
    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        auto iter = conn_map_.find(head->client_id);
        if (iter == conn_map_.end()) {
            return kVpnsvrSuccess;
        }

        route_server = iter->second;
    }

//     for (uint32_t i = 0; i < 5; ++i) {
        ConnectStreamServer(head->client_id, route_server);
//     }
    return kVpnsvrSuccess;
}

void TcpRelayClientManager::RotationConnectStreamServer() {
    std::unordered_map<uint32_t, RouteServer> conn_map;
    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        conn_map = conn_map_;
    }

    for (auto iter = conn_map.begin(); iter != conn_map.end(); ++iter) {
        ConnectStreamServer(iter->first, iter->second);
    }

    rotation_tick_.CutOff(
            kStreamRotationPeriod,
            std::bind(&TcpRelayClientManager::RotationConnectStreamServer, this));

}

void TcpRelayClientManager::RotationConnectServer() {
    std::unordered_map<uint32_t, RouteServer> conn_map;
    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        conn_map = conn_map_;
    }

    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    for (auto iter = conn_map.begin(); iter != conn_map.end(); ++iter) {
        auto tcp_conn = CreateAndHandshake(now_timestamp_days, iter->second);
        if (tcp_conn == nullptr) {
            std::lock_guard<std::mutex> guard(conn_map_mutex_);
            conn_map_.erase(conn_map_.begin());
        }
    }

//     rotation_tick_.CutOff(
//             kRotationPeriod,
//             std::bind(&TcpRelayClientManager::RotationConnectServer, this));
}

VlanConnection* TcpRelayClientManager::ConnectStreamServer(
        uint32_t client_id,
        const RouteServer& route_svr) {
    {
        std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
        auto stream_iter = stream_conn_map_.find(client_id | 0x80000000u);
        if (stream_iter != stream_conn_map_.end()) {
            if (stream_iter->second.size() > 10) {
                return nullptr;
            }
        }
    }

    auto timestamp_day = common::TimeUtils::TimestampDays();
    auto port = common::GetVpnRoutePort(
            route_svr.dht_key,
            timestamp_day,
            route_svr.min_stream_port,
            route_svr.max_stream_port);
    auto tcp_conn = new VlanConnection();
    if (tcp_conn->Connect(route_svr.ip, port) != 0) {
        delete tcp_conn;
        return nullptr;
    }

    if (StreamHandshake(client_id, tcp_conn, route_svr) != kVpnsvrSuccess) {
        delete tcp_conn;
        return nullptr;
    }

    tcp_conn->remote_->hold_by_valn_queue = true;
    tcp_conn->set_id(client_id | 0x80000000u);
    {
        static uint32_t connect_times = 0;
        std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
        auto stream_iter = stream_conn_map_.find(tcp_conn->id());
        if (stream_iter == stream_conn_map_.end()) {
            std::deque<VlanConnection*> tmp_queue;
            tmp_queue.push_back(tcp_conn);
            stream_conn_map_[tcp_conn->id()] = tmp_queue;
            return tcp_conn;
        }

        stream_iter->second.push_back(tcp_conn);
    }

    return tcp_conn;
}

int TcpRelayClientManager::SendStreamPacket(
        uint32_t stream_id,
        uint32_t server_id,
        const char* data,
        uint32_t len,
        remote_t* real_remote) {
    while (true) {
        auto stream_iter = stream_conn_map_.find(stream_id);
        if (stream_iter == stream_conn_map_.end() || stream_iter->second.empty()) {
            return 1;
        }

        VlanConnection* tcp_con = stream_iter->second.back();
        if (!tcp_con->SendPacket(data, len, real_remote)) {
            delete tcp_con;
            stream_iter->second.pop_back();
            continue;
        }

        break;
    }

    return 0;
}

VlanConnection* TcpRelayClientManager::GetStreamConn(uint32_t stream_conid) {
    std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
    auto stream_iter = stream_conn_map_.find(stream_conid);
    if (stream_iter == stream_conn_map_.end() || stream_iter->second.empty()) {
        return nullptr;
    }

    return stream_iter->second.back();
}

void TcpRelayClientManager::EraseStreamConn(VlanConnection* tcp_con) {
    std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
    auto stream_iter = stream_conn_map_.find(tcp_con->id());
    if (stream_iter == stream_conn_map_.end() || stream_iter->second.empty()) {
        return;
    }

    auto iter = std::find(stream_iter->second.begin(), stream_iter->second.end(), tcp_con);
    if (iter != stream_iter->second.end()) {
        stream_iter->second.erase(iter);
        if (stream_iter->second.empty()) {
            stream_conn_map_.erase(stream_iter);
        }
    }
}

int TcpRelayClientManager::SendStopServer(uint32_t stream_id, uint32_t server_id) {
    return 0;
    char stream_data[SOCKET_BUF_SIZE + sizeof(uint32_t)];
    uint32_t* head = (uint32_t*)(stream_data);
    head[0] = common::HeaderType::Instance()->GetRandNum(common::kStreamStopServer);
    head[1] = common::kStreamMagicNum;
    head[2] = server_id;
    buffer_t buf;
    buf.data = stream_data + sizeof(uint32_t);
    buf.len = sizeof(uint32_t) * 2;
    buf.capacity = SOCKET_BUF_SIZE;
    buf.idx = 0;
    common::HeaderType::Instance()->Encrypt(head[0], &buf);
    std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
    auto stream_iter = stream_conn_map_.find(stream_id);
    if (stream_iter != stream_conn_map_.end()) {
        if (!stream_iter->second.empty()) {
            if (!stream_iter->second.back()->SendPacket(stream_data, sizeof(uint32_t) + buf.len, NULL)) {
                return kVpnsvrError;
            }
        }
    }

    return kVpnsvrSuccess;
}

int TcpRelayClientManager::StreamHandshake(
        uint32_t client_id,
        VlanConnection* tcp_conn,
        const RouteServer& route_svr) {
    char stream_data[SOCKET_BUF_SIZE + sizeof(uint32_t)];
    uint32_t* head = (uint32_t*)(stream_data);
    head[0] = common::HeaderType::Instance()->GetRandNum(common::kStreamConnect);
    head[1] = common::kStreamMagicNum;
    head[2] = client_id;
    head[3] = route_svr.local_ip_int;
    uint16_t* local_port = (uint16_t*)(head + 4);
    local_port[0] = route_svr.local_port;
    buffer_t buf;
    buf.data = stream_data + sizeof(uint32_t);
    buf.len = sizeof(uint32_t) * 3 + sizeof(uint16_t);
    buf.capacity = SOCKET_BUF_SIZE;
    buf.idx = 0;
    common::HeaderType::Instance()->Encrypt(head[0], &buf);
    if (!tcp_conn->SendPacket(stream_data, sizeof(uint32_t) + buf.len, NULL)) {
        return kVpnsvrError;
    }

    return kVpnsvrSuccess;
}

VlanConnection* TcpRelayClientManager::CreateAndHandshake(
        uint32_t timestamp_day,
        const RouteServer& route_svr) {
    auto port = common::GetVpnServerPort(
            route_svr.dht_key,
            timestamp_day,
            route_svr.min_port,
            route_svr.max_port);
    auto tcp_conn = new VlanConnection();
    if (tcp_conn->Connect(route_svr.ip, port) != 0) {
        delete tcp_conn;
        return nullptr;
    }

    if (Handshake(tcp_conn) != kVpnsvrSuccess) {
        delete tcp_conn;
        return nullptr;
    }

    return tcp_conn;
}

void TcpRelayClientManager::RemoveVlanRemote(VlanConnection* vlan_conn) {
    uint32_t client_id = (vlan_conn->id() & 0x7FFFFFFFu);
    RouteServer route_server;
    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        auto iter = conn_map_.find(client_id);
        if (iter == conn_map_.end()) {
            return;
        }

        route_server = iter->second;
    }

    ConnectStreamServer(client_id, route_server);
    {
        std::lock_guard<std::mutex> guard(stream_conn_map_mutex_);
        auto stream_iter = stream_conn_map_.find(vlan_conn->id());
        if (stream_iter != stream_conn_map_.end()) {
            auto qiter = std::find(stream_iter->second.begin(), stream_iter->second.end(), vlan_conn);
            if (qiter != stream_iter->second.end()) {
                stream_iter->second.erase(qiter);
            }
        }
    }
}

void TcpRelayClientManager::HandleMessage(
        VlanConnection* conn,
        char* msg,
        uint32_t len) {
    if (msg == nullptr) {
        // free connection
        if ((conn->id() & 0x80000000u) == 0x80000000u) {
            EraseStreamConn(conn);
            RemoveVlanRemote(conn);
        }

        return;
    }

    conn->set_data(msg, len);
    if (conn->get_data_len() < (sizeof(TnetWithRelayHead))) {
        return;
    }

    char* tmp_msg = conn->get_data_buf();
    uint32_t tmp_len = conn->get_data_len();
    while (true) {
        if (tmp_len < (sizeof(TnetWithRelayHead))) {
            conn->shift_data(tmp_msg, tmp_len);
            break;
        }

        TnetWithRelayHead* header = (TnetWithRelayHead*)tmp_msg;
        if (header->header.magic != transport::kTcpPacketMagicNumber) {
            delete &transport::kTcpPacketMagicNumber;
            break;
        }

        if (header->header.length + sizeof(transport::PacketHeader) > tmp_len) {
            conn->shift_data(tmp_msg, tmp_len);
            break;
        }

        buffer_t* new_buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
        balloc(new_buf, sizeof(transport::PacketHeader) + header->header.length);
        memcpy(new_buf->data, tmp_msg, sizeof(transport::PacketHeader) + header->header.length);
        new_buf->len = sizeof(transport::PacketHeader) + header->header.length;
        in_buffer_queue_.push_back({ new_buf, conn });
        tmp_msg += (header->header.length + sizeof(transport::PacketHeader));
        tmp_len -= (header->header.length + sizeof(transport::PacketHeader));
    }

    for (auto iter = in_buffer_queue_.begin(); iter != in_buffer_queue_.end();) {
        TnetWithRelayHead* header = (TnetWithRelayHead*)iter->new_buf->data;
        if (header->header.length == (sizeof(TcpRelayHead) + 6)) {
            HandleVlanMessage(header, iter->conn);
            iter = in_buffer_queue_.erase(iter);
            continue;
        }
            
        ServerKey key;
        key.ids.id = header->relay_head.server_id;
        key.ids.stream_id = iter->conn->id();
        auto miter = remote_status_map_.find(key.key);
        if (miter != remote_status_map_.end()) {
            if (miter->second == -1) {
                ++iter;
                std::cout << "wait to send to internet." << std::endl;
                continue;
            }

            if (miter->second == 1) {
                bfree(iter->new_buf);
                ss_free(iter->new_buf);
                iter = in_buffer_queue_.erase(iter);
                continue;
            }
        }

        int res = HandleVlanMessage(header, iter->conn);
        if (res == -1) {
            remote_status_map_[key.key] = -1;
            ++iter;
            std::cout << "wait to send to internet." << std::endl;
            continue;
        }

        bfree(iter->new_buf);
        ss_free(iter->new_buf);
        iter = in_buffer_queue_.erase(iter);
    }
}
    
int TcpRelayClientManager::HandleVlanMessage(TnetWithRelayHead* tnet_header, VlanConnection* conn) {
    if (tnet_header->header.length == (sizeof(TcpRelayHead) + 6)) {
        if (tnet_header->relay_head.client_id == 0) {
            uint32_t drop_server_tag = *(uint32_t*)(tnet_header + 1);
            if (drop_server_tag == kRouteServerClosed) {
                recv_callback_(tnet_header->relay_head.server_id, 0, NULL, 0);
                return 0;
            }

            if (drop_server_tag == kRemoteServerClosed) {
                RemoveVlanRemote(conn);
                return 0;
            }
        }

        if (conn->id() != 0) {
            Handshake(conn);
            return 0;
        }

        if (tnet_header->relay_head.client_id == 0) {
            return 0;
        }

        conn->set_id(tnet_header->relay_head.client_id);
        RouteServer route_server;
        {
            std::lock_guard<std::mutex> guard(tmp_conn_map_mutex_);
            auto iter = tmp_conn_map_.find(conn);
            if (iter == tmp_conn_map_.end()) {
                return 0;
            }

            route_server = iter->second;
            tmp_conn_map_.erase(iter);
        }

        uint32_t* ip_int = (uint32_t*)(tnet_header + 1);
        route_server.local_ip_int = *ip_int;
        route_server.local_port = *(uint16_t*)(ip_int + 1);
        {
            std::lock_guard<std::mutex> guard(conn_map_mutex_);
            auto iter = conn_map_.find(tnet_header->relay_head.client_id);
            if (iter == conn_map_.end()) {
                conn_map_[tnet_header->relay_head.client_id] = route_server;
            }
        }

        HandshakeDetail(conn);
        return 0;
    }

    if ((conn->id() & 0x80000000u) != 0x80000000u) {
        return 0;
    }

    return recv_callback_(
            tnet_header->relay_head.server_id,
            conn->id(),
            (char*)(tnet_header + 1),
            tnet_header->header.length - sizeof(TcpRelayHead));
}

}  // namespace vpn

}  // namespace tenon
