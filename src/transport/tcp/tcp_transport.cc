#include "stdafx.h"
#include "transport/tcp/tcp_transport.h"

#include "common/global_info.h"
#include "common/time_utils.h"
#include "transport/transport_utils.h"
#include "transport/multi_thread.h"
#include "transport/proto/transport.pb.h"
#include "transport/message_filter.h"
#include "init/update_vpn_init.h"

namespace tenon {

namespace transport {

using namespace tnet;
#ifdef CLIENT_USE_UV
// single loop, thread safe
static uv_loop_t loop;
TcpTransport* tcp_transport = nullptr;
uv_tcp_t* socket;
uv_os_sock_t sock;

struct connect_ex_t {
    uv_connect_t uv_conn;
    std::string* msg;
};

struct ex_uv_tcp_t {
    uv_tcp_t uv_tcp;
    MsgDecoder* msg_decoder;
    char ip[64];
    uint16_t port;
};

#ifdef _WIN32

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;

    memset(&ss, sizeof(ss), 0);
    ss.ss_family = af;

    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
        break;
    default:
        return NULL;
    }

    const size_t cSize = strlen(dst) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, dst, cSize);
    char* res = (WSAAddressToStringW((struct sockaddr *)&ss, sizeof(ss), NULL, wc, &s) == 0) ?
        dst : NULL;
    delete[]wc;
    return res;
}

#endif // _WIN32

static void get_peer_ip_port(uv_tcp_t* tcp, std::string* ip, uint16_t *port) {
    struct sockaddr sockname;
    memset(&sockname, -1, sizeof sockname);
    int namelen = sizeof(sockname);
    uv_tcp_getpeername(tcp, &sockname, &namelen);
    struct sockaddr_in *sock = (struct sockaddr_in*)&sockname;
    *port = ntohs(sock->sin_port);
    struct in_addr in = sock->sin_addr;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, str, sizeof(str));
    *ip = str;
}

bool OnClientPacket(const std::string& from_ip, uint16_t from_port, tnet::Packet& packet) {
    MsgPacket* msg_packet = dynamic_cast<MsgPacket*>(&packet);
    char* data = nullptr;
    uint32_t len = 0;
    msg_packet->GetMessageEx(&data, &len);
    if (data == nullptr) {
        return false;
    }

    MultiThreadHandler::Instance()->HandleMessage(
            nullptr,
            from_ip,
            from_port,
            data,
            len,
            1);
    packet.Free();
    return true;
}

static void alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
    *buf = uv_buf_init((char*)malloc(size), size);
}

void on_close(uv_handle_t* handle) {
    TRANSPORT_ERROR("close called!");
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)handle;
    delete ex_uv_tcp->msg_decoder;
    free(ex_uv_tcp);
}

void on_write(uv_write_t* req, int status) {
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)req->handle;
    TRANSPORT_ERROR("on_write called back.");
    if (status) {
//         tcp_transport->FreeConnection(ex_uv_tcp->ip, ex_uv_tcp->port);
//         uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, on_close);
//         free(req);
//         return;
    }

    free(req);
}

void on_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)tcp;
    if (nread >= 0) {
        ex_uv_tcp->msg_decoder->Decode(buf->base, nread);
        auto packet = ex_uv_tcp->msg_decoder->GetPacket();
        while (packet != nullptr) {
            OnClientPacket(ex_uv_tcp->ip, ex_uv_tcp->port, *packet);
            packet = ex_uv_tcp->msg_decoder->GetPacket();
        }
    } else {
        // TODO(xiel): check it
        uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, on_close);
        tcp_transport->FreeConnection(ex_uv_tcp->ip, ex_uv_tcp->port);
    }

    free(buf->base);
}

void on_connect(uv_connect_t* connection, int status) {
    uv_stream_t* stream = connection->handle;
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)stream;
    if (status < 0) {
        printf("failed to connect %s, %d\n", ex_uv_tcp->ip, ex_uv_tcp->port);
        uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, on_close);
        tcp_transport->FreeConnection(ex_uv_tcp->ip, ex_uv_tcp->port);
        connect_ex_t* ex_conn = (connect_ex_t*)connection;
        delete ex_conn->msg;
        free(ex_conn);
        return;
    }

    tcp_transport->AddConnection(ex_uv_tcp->ip, ex_uv_tcp->port, stream);
    uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
    connect_ex_t* ex_conn = (connect_ex_t*)connection;
    uv_buf_t uv_buf = uv_buf_init((char*)ex_conn->msg->c_str(), ex_conn->msg->size());
    uv_write(req, (uv_stream_t*)&ex_uv_tcp->uv_tcp, &uv_buf, 1, on_write);
    delete ex_conn->msg;
    free(ex_conn);
    uv_read_start((uv_stream_t*)&ex_uv_tcp->uv_tcp, alloc_cb, on_read);
}

TcpTransport::TcpTransport(const std::string& ip_port, int backlog, bool create_server)
    : ip_port_(ip_port), backlog_(backlog), create_server_(create_server) {
    tcp_transport = this;
}

TcpTransport::~TcpTransport() {}

int TcpTransport::Init() {
    //     loop = *uv_default_loop();
    memset(&loop, 0, sizeof(uv_loop_t));
    uv_loop_init(&loop);
    return kTransportSuccess;
}

int TcpTransport::Start(bool hold) {
    if (hold) {
        Run();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&TcpTransport::Run, this));
        run_thread_->detach();
    }

    return kTransportSuccess;
}

void TcpTransport::Stop() {
    free(handle_);
    uv_loop_close(&loop);
}

int TcpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        const transport::protobuf::Header& message) {
    std::string des_ip = ip;
    uint16_t des_port = port;
    if (common::GlobalInfo::Instance()->is_client() && (
            message.type() == common::kBlockMessage ||
            message.type() == common::kBftMessage)) {
        std::string tmp_ip;
        uint16_t tmp_port = 0;
        if (init::UpdateVpnInit::Instance()->GetBftNode(
                &tmp_ip,
                &tmp_port) != init::kInitError) {
            des_ip = tmp_ip;
            des_port = tmp_port + 1;
        }
    }

    if (!message.has_version()) {
        message.set_version(kTransportVersionNum);
    }

    if (!message.has_hash() || message.hash() == 0) {
        message.set_hash(GetMessageHash(message));
    }

    uv_stream_t* stream = GetConnection(des_ip, des_port);
    if (stream == nullptr) {
        ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)malloc(sizeof(ex_uv_tcp_t));
        memset(ex_uv_tcp, 0, sizeof(ex_uv_tcp_t));
        uv_tcp_init(&loop, &ex_uv_tcp->uv_tcp);
        struct sockaddr_in server_addr;
        uv_ip4_addr(des_ip.c_str(), des_port, &server_addr);
        connect_ex_t* ex_conn = (connect_ex_t*)malloc(sizeof(connect_ex_t));
        std::string* msg = new std::string();
        std::string tmp_msg;
        message.SerializeToString(&tmp_msg);
        PacketHeader header(tmp_msg.size(), 0);
        msg->append((char*)&header, sizeof(header));
        msg->append(tmp_msg);
        ex_conn->msg = msg;
        ex_uv_tcp->msg_decoder = new MsgDecoder();
        memcpy(ex_uv_tcp->ip, des_ip.c_str(), sizeof(ex_uv_tcp->ip) - 1);
        ex_uv_tcp->port = des_port;
        uv_tcp_connect(&ex_conn->uv_conn, &ex_uv_tcp->uv_tcp, (const struct sockaddr*)&server_addr, on_connect);
    } else {
        std::string msg;
        message.SerializeToString(&msg);
        std::string tmp_msg;
        PacketHeader header(msg.size(), 0);
        tmp_msg.append((char*)&header, sizeof(header));
        tmp_msg.append(msg);
        uv_buf_t buf = uv_buf_init((char*)tmp_msg.c_str(), tmp_msg.size());
        uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
        ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)stream;
        uv_write(req, (uv_stream_t*)&ex_uv_tcp->uv_tcp, &buf, 1, on_write);
    }

    return kTransportSuccess;
}

int TcpTransport::SendToLocal(const transport::protobuf::Header& message) {
    message.clear_broadcast();
    MultiThreadHandler::Instance()->HandleMessage(message);
    return kTransportSuccess;
}

int TcpTransport::GetSocket() {
    return kTransportSuccess;
}

void TcpTransport::FreeConnection(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    std::string peer_spec = ip + ":" + std::to_string(port);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        TRANSPORT_ERROR("FreeConnection called!");
        uv_close((uv_handle_t*)iter->second, on_close);
        conn_map_.erase(iter);
    }
}

void TcpTransport::Run() {
#ifndef WIN32
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (rc != 0) {
        printf("block sigpipe error/n");
    }
#endif        
    while (true) {
        if (uv_run(&loop, UV_RUN_DEFAULT) != 0) {
            TRANSPORT_ERROR("uv run failed!");
        }

        std::this_thread::sleep_for(std::chrono::microseconds(10000ull));
    }
}

uv_stream_t* TcpTransport::GetConnection(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    std::string peer_spec = ip + ":" + std::to_string(port);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        return iter->second;
    }

    return nullptr;
}

void TcpTransport::AddConnection(const std::string& ip, uint16_t port, uv_stream_t* stream) {
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    std::string peer_spec = ip + ":" + std::to_string(port);
    conn_map_[peer_spec] = stream;
}

uint64_t TcpTransport::GetMessageHash(transport::protobuf::Header& message) {
    auto hash = common::Hash::Hash64(
        "tcp" + message.src_node_id() + std::to_string(message.id()) + message.data());
    return hash;
}

std::string TcpTransport::ClearAllConnection() {
    std::string res;
//     std::lock_guard<std::mutex> guard(tcp_transport->send_mutex_);
//     for (auto iter = conn_map_.begin(); iter != conn_map_.end(); ++iter) {
//         if (iter->second == nullptr) {
//             continue;
//         }
// 
//         uv_close((uv_handle_t*)iter->second, on_close);
//     }
// 
//     conn_map_.clear();
    return res;
}

#else

TcpTransport::TcpTransport(const std::string& ip_port, int backlog, bool create_server)
        : ip_port_(ip_port), backlog_(backlog), create_server_(create_server) {
    EraseConn();
}

TcpTransport::~TcpTransport() {}

int TcpTransport::Init() {
    auto packet_handler = std::bind(
            &TcpTransport::OnClientPacket,
            this,
            std::placeholders::_1,
            std::placeholders::_2);
    if (common::GlobalInfo::Instance()->is_client()) {
        transport_ = std::make_shared<TnetTransport>(
            true,
            100 * 1024,
            100 * 1024,
            1,
            packet_handler,
            &encoder_factory_);
    } else {
        transport_ = std::make_shared<TnetTransport>(
            true,
            10 * 1024 * 1024,
            10 * 1024 * 1024,
            1,
            packet_handler,
            &encoder_factory_);
    }
    if (!transport_->Init()) {
        TRANSPORT_ERROR("transport init failed");
        return kTransportError;
    }

    if (!create_server_) {
        return kTransportSuccess;
    }

    acceptor_ = dynamic_cast<TcpAcceptor*>(transport_->CreateAcceptor(nullptr));
    if (acceptor_ == NULL) {
        TRANSPORT_ERROR("create acceptor failed");
        return kTransportError;
    }

    socket_ = SocketFactory::CreateTcpListenSocket(ip_port_);
    if (socket_ == NULL) {
        TRANSPORT_ERROR("create socket failed");
        return kTransportError;
    }

    if (!socket_->SetNonBlocking(true) || !socket_->SetCloseExec(true)) {
        TRANSPORT_ERROR("set non-blocking or close-exec failed");
        return kTransportError;
    }

    if (!socket_->Listen(backlog_)) {
        TRANSPORT_ERROR("listen socket failed");
        return kTransportError;
    }

    acceptor_->SetListenSocket(*socket_);
    if (!acceptor_->Start()) {
        TRANSPORT_ERROR("start acceptor failed");
        return kTransportError;
    }

    return kTransportSuccess;
}

TcpAcceptor* TcpTransport::CreateNewServer(
        const std::string& ip,
        uint16_t port) {
    auto acceptor = dynamic_cast<TcpAcceptor*>(transport_->CreateAcceptor(nullptr));
    if (acceptor == NULL) {
        TRANSPORT_ERROR("create acceptor failed");
        return nullptr;
    }

    std::string ip_port = ip + ":" + std::to_string(port);
    auto socket = SocketFactory::CreateTcpListenSocket(ip_port);
    if (socket == NULL) {
        TRANSPORT_ERROR("create socket failed");
        return nullptr;
    }

    if (!socket->SetNonBlocking(true) || !socket->SetCloseExec(true)) {
        TRANSPORT_ERROR("set non-blocking or close-exec failed");
        return nullptr;
    }

    if (!socket->Listen(backlog_)) {
        TRANSPORT_ERROR("listen socket failed");
        return nullptr;
    }

    acceptor->SetListenSocket(*socket);
    if (!acceptor->Start()) {
        TRANSPORT_ERROR("start acceptor failed");
        return nullptr;
    }

    return acceptor;
}

int TcpTransport::CreateNewServer(
        const std::string& ip,
        const std::string& dh_key,
        uint32_t timestamp,
        uint16_t min_port,
        uint16_t max_port,
        std::set<uint16_t>& except_ports) {
    uint16_t node_port = common::GetNodePort(dh_key, timestamp, min_port, max_port);
    if (except_ports.find(node_port) != except_ports.end()) {
        return kTransportSuccess;
    }

    except_ports.insert(node_port);
    auto acceptor = dynamic_cast<TcpAcceptor*>(transport_->CreateAcceptor(nullptr));
    if (acceptor == NULL) {
        TRANSPORT_ERROR("create acceptor failed");
        return kTransportError;
    }

    std::string ip_port = ip + ":" + std::to_string(node_port);
    auto socket = SocketFactory::CreateTcpListenSocket(ip_port);
    if (socket == NULL) {
        TRANSPORT_ERROR("create socket failed");
        return kTransportError;
    }

    if (!socket->SetNonBlocking(true) || !socket->SetCloseExec(true)) {
        TRANSPORT_ERROR("set non-blocking or close-exec failed");
        return kTransportError;
    }

    if (!socket->Listen(backlog_)) {
        TRANSPORT_ERROR("listen socket failed");
        return kTransportError;
    }

    acceptor->SetListenSocket(*socket);
    if (!acceptor->Start()) {
        TRANSPORT_ERROR("start acceptor failed");
        return kTransportError;
    }

    rotation_servers_.push_back({ acceptor, socket, node_port });
    return kTransportSuccess;
}

void TcpTransport::DestroyTailServer(
        uint32_t keep_server_count,
        std::set<uint16_t>& except_ports) {
    if (rotation_servers_.size() <= keep_server_count) {
        return;
    }

    auto tail_server = rotation_servers_.back();
    if (tail_server.acceptor != nullptr) {
        tail_server.acceptor->Stop();
        tail_server.acceptor->Destroy();
    }

    auto iter = except_ports.find(tail_server.port);
    if (iter != except_ports.end()) {
        except_ports.erase(iter);
    }

    rotation_servers_.pop_back();
}

int TcpTransport::Start(bool hold) {
    transport_->Dispatch();
    if (!transport_->Start()) {
        return kTransportError;
    }

    return kTransportSuccess;
}

void TcpTransport::Stop() {
    if (acceptor_ != nullptr) {
        acceptor_->Stop();
        acceptor_->Destroy();
    }

    if (transport_) {
        transport_->Stop();
        transport_->Destroy();
    }
}

bool TcpTransport::OnClientPacket(tnet::TcpConnection* conn, tnet::Packet& packet) {
    auto tcp_conn = dynamic_cast<tnet::TcpConnection*>(conn);
    if (conn->GetSocket() == nullptr) {
        packet.Free();
        return false;
    }

    std::string from_ip;
    uint16_t from_port;
    conn->GetSocket()->GetIpPort(&from_ip, &from_port);
    if (packet.IsCmdPacket()) {
        if (raw_callback_ != nullptr) {
            raw_callback_(tcp_conn, nullptr, 0);
        }

        FreeConnection(from_ip, from_port);
        packet.Free();
        return false;
    }

    // network message must free memory
    MsgPacket* msg_packet = dynamic_cast<MsgPacket*>(&packet);
    char* data = nullptr;
    uint32_t len = 0;
    msg_packet->GetMessageEx(&data, &len);
    if (msg_packet->PacketType() == 1 && raw_callback_ != nullptr) {
        if (data == nullptr) {
            return false;
        }

        raw_callback_(tcp_conn, data, len);
        packet.Free();
        return true;
    }

    AddClientConnection(tcp_conn);
    MultiThreadHandler::Instance()->HandleMessage(
            from_ip,
            from_port,
            data,
            len,
            kTcp);
    packet.Free();
    return true;
}

uint64_t TcpTransport::GetMessageHash(const transport::protobuf::Header& message) {
    auto hash = common::Hash::Hash64(
        "tcp" + common::GlobalInfo::Instance()->id() + std::to_string(message.id()) +
        std::to_string(common::TimeUtils::TimestampUs()));
    return hash;
}

int TcpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        const transport::protobuf::Header& message) {
    std::string des_ip = ip;
    uint16_t des_port = port;
    if (common::GlobalInfo::Instance()->is_client() && (
            message.type() == common::kBlockMessage ||
            message.type() == common::kBftMessage)) {
        std::string tmp_ip;
        uint16_t tmp_port = 0;
        if (init::UpdateVpnInit::Instance()->GetBftNode(
                &tmp_ip,
                &tmp_port) != init::kInitError) {
            des_ip = tmp_ip;
            des_port = tmp_port + 1;
        }
    }

    std::string msg;
    if (!message.has_hash() || message.hash() == 0) {
        auto cast_msg = const_cast<transport::protobuf::Header*>(&message);
        cast_msg->set_hash(GetMessageHash(message));
    }

    if (message.has_broadcast()) {
        MessageFilter::Instance()->CheckUnique(message.hash());
    }

    message.SerializeToString(&msg);
    MsgPacket* reply_packet = new MsgPacket(0, tnet::kEncodeWithHeader, false);
    // local message is thread safe and don't free memory
    reply_packet->SetMessage(&msg);
    auto tcp_conn = GetConnection(des_ip, des_port);
    if (tcp_conn == nullptr) {
        reply_packet->Free();
        TRANSPORT_ERROR("get tcp connection failed[%s][%d][id: %llu]",
            des_ip.c_str(), des_port, message.id());
        return kTransportError;
    }

    if (!tcp_conn->SendPacket(*reply_packet)) {
        reply_packet->Free();
        FreeConnection(des_ip, des_port);
        return kTransportError;
    }

//     if (message.has_debug()) {
//         TRANSPORT_ERROR("%s send message id: %lu, has_broadcast: %d, type: %d, to: %s:%d, debug: %s, msg hash: %lu, des net id: %s",
//             message.debug().c_str(),
//             message.id(), message.has_broadcast(), message.type(), des_ip.c_str(), des_port, message.debug().c_str(), message.hash(), common::Encode::HexEncode(message.des_dht_key()).c_str());
//     }
    return kTransportSuccess;
}

int TcpTransport::SendToLocal(const transport::protobuf::Header& message) {
    auto cast_msg = const_cast<transport::protobuf::Header*>(&message);
    cast_msg->clear_broadcast();
    if (!message.has_hash() || message.hash() == 0) {
        cast_msg->set_hash(GetMessageHash(message));
    }

    MessageFilter::Instance()->CheckUnique(message.hash());
    MultiThreadHandler::Instance()->HandleMessage(message);
    return kTransportSuccess;
}

int TcpTransport::GetSocket() {
    return socket_->GetFd();
}

void TcpTransport::FreeConnection(const std::string& ip, uint16_t port) {
    std::string peer_spec = ip + ":" + std::to_string(port);
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        iter->second->Destroy(true);
        std::lock_guard<std::mutex> guard(erase_conns_mutex_);
        erase_conns_.push_back(iter->second);
        conn_map_.erase(iter);
    }
}

tnet::TcpConnection* TcpTransport::CreateConnection(const std::string& ip, uint16_t port) {
    if (ip == "0.0.0.0") {
        return nullptr;
    }

    std::string peer_spec = ip + ":" + std::to_string(port);
    return transport_->CreateConnection(
            peer_spec,
            common::GlobalInfo::Instance()->tcp_spec(),
            300u * 1000u * 1000u);
}

tnet::TcpConnection* TcpTransport::GetConnection(const std::string& ip, uint16_t port) {
    if (ip == "0.0.0.0") {
        return nullptr;
    }

    std::string peer_spec = ip + ":" + std::to_string(port);
    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        auto iter = conn_map_.find(peer_spec);
        if (iter != conn_map_.end()) {
            if (iter->second->GetTcpState() == tnet::TcpConnection::kTcpClosed) {
                std::lock_guard<std::mutex> guard(erase_conns_mutex_);
                erase_conns_.push_back(iter->second);
                conn_map_.erase(iter);
            } else {
                return iter->second;
            }
        }
    }

    auto tcp_conn = transport_->CreateConnection(
            peer_spec,
            common::GlobalInfo::Instance()->tcp_spec(),
            3u * 1000u * 1000u);
    if (tcp_conn == nullptr) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> guard(conn_map_mutex_);
        auto iter = conn_map_.find(peer_spec);
        if (iter != conn_map_.end()) {
            std::lock_guard<std::mutex> guard(erase_conns_mutex_);
            erase_conns_.push_back(iter->second);
            iter->second->Destroy(true);
            conn_map_.erase(iter);
        }

        conn_map_[peer_spec] = tcp_conn;
//         TRANSPORT_DEBUG("0 MMMMMMMM now con map size: %u", conn_map_.size());
    }
    return tcp_conn;
}

std::string TcpTransport::ClearAllConnection() {
    std::string res;
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    for (auto iter = conn_map_.begin(); iter != conn_map_.end(); ++iter) {
        if (iter->second == nullptr || iter->second->GetSocket() == nullptr) {
            continue;
        }

        res += std::to_string(iter->second->GetSocket()->GetFd()) + ",";
    }

    return res;
}

void TcpTransport::AddClientConnection(tnet::TcpConnection* conn) {
    std::string client_ip;
    uint16_t client_port;
    if (conn->GetSocket()->GetIpPort(&client_ip, &client_port) != 0) {
        return;
    }

    std::string peer_spec = client_ip + ":" + std::to_string(client_port);
    std::lock_guard<std::mutex> guard(conn_map_mutex_);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        if (iter->second == conn) {
            return;
        }

        iter->second->Destroy(true);
        std::lock_guard<std::mutex> guard(erase_conns_mutex_);
        erase_conns_.push_back(iter->second);
        conn_map_.erase(iter);
    }

    conn_map_[peer_spec] = conn;
//     TRANSPORT_DEBUG("1 MMMMMMMM now con map size: %u", conn_map_.size());
}

void TcpTransport::EraseConn() {
    auto now_tm_ms = common::TimeUtils::TimestampMs();
    // delay to release
    std::lock_guard<std::mutex> guard(erase_conns_mutex_);
    while (!erase_conns_.empty()) {
        auto from_item = erase_conns_.front();
        if (from_item->free_timeout_ms() <= now_tm_ms) {
            delete from_item;
            erase_conns_.pop_front();
            continue;
        }

        break;
    }

    erase_conn_tick_.CutOff(kEraseConnPeriod, std::bind(&TcpTransport::EraseConn, this));
}

#endif // CLIENT_USE_UV

}  // namespace transport

}  // namespace tenon
