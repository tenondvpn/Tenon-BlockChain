#pragma once

#include <memory>
#include <unordered_map>
#include <set>

//#define CLIENT_USE_UV
#ifdef CLIENT_USE_UV
#include "uv/uv.h"
#else
#include "tnet/tnet_transport.h"
#include "tnet/tcp_connection.h"
#include "tnet/tcp_acceptor.h"
#include "tnet/utils/packet.h"
#include "tnet/utils/cmd_packet.h"
#include "tnet/socket/socket_factory.h"
#include "tnet/socket/listen_socket.h"
#endif // CLIENT_USE_UV
#include "transport/tcp/msg_decoder.h"
#include "transport/tcp/msg_encoder.h"
#include "transport/tcp/encoder_factory.h"
#include "transport/tcp/msg_packet.h"
#include "transport/transport.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace transport {

class TcpTransport : public Transport {
public:
    TcpTransport(const std::string& ip_port, int backlog, bool create_server);
    ~TcpTransport();
    virtual int Init();
    virtual int Start(bool hold);
    virtual void Stop();
    virtual int Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        transport::protobuf::Header& message);
    virtual int SendToLocal(transport::protobuf::Header& message);
    virtual int GetSocket();
    virtual void FreeConnection(const std::string& ip, uint16_t port);
#ifdef CLIENT_USE_UV
    void* CreateNewServer(
            const std::string& ip,
            uint16_t port) {
        return nullptr;
     }
    void AddConnection(const std::string& ip, uint16_t port, uv_stream_t* stream);
    std::mutex send_mutex_;
#else
    tnet::TcpAcceptor* CreateNewServer(
        const std::string& ip,
        uint16_t port);
    void SetRawCallback(TcpRawPacketCallback raw_callback) {
        raw_callback_ = raw_callback;
    }
    std::shared_ptr<tnet::TcpConnection> GetConnection(const std::string& ip, uint16_t port);
    std::shared_ptr<tnet::TcpConnection> CreateConnection(const std::string& ip, uint16_t port);
#endif

    int CreateNewServer(
            const std::string& ip,
            const std::string& dh_key,
            uint32_t timestamp,
            uint16_t min_port,
            uint16_t max_port,
            std::set<uint16_t>& except_ports);
    void DestroyTailServer(uint32_t keep_server_count, std::set<uint16_t>& except_ports);
    std::string ClearAllConnection();

private:
    uint64_t GetMessageHash(transport::protobuf::Header& message);
#ifdef CLIENT_USE_UV
    uv_stream_t* GetConnection(const std::string& ip, uint16_t port);
    std::shared_ptr<std::thread> run_thread_{ nullptr };
    uv_udp_t* handle_{ nullptr };
    std::unordered_map<std::string, uv_stream_t*> conn_map_;

#else
    struct RotationServer {
        tnet::TcpAcceptor* acceptor;
        tnet::ListenSocket* socket;
        uint16_t port;
    };

    bool OnClientPacket(std::shared_ptr<tnet::TcpConnection> conn, tnet::Packet& packet);
    void AddClientConnection(std::shared_ptr<tnet::TcpConnection>& conn);
    std::shared_ptr<tnet::TnetTransport> transport_{ nullptr };
    tnet::TcpAcceptor* acceptor_{ nullptr };
    EncoderFactory encoder_factory_;
    tnet::ListenSocket* socket_{ nullptr };
    std::deque<RotationServer> rotation_servers_;
    std::unordered_map<std::string, std::shared_ptr<tnet::TcpConnection>> conn_map_;
    TcpRawPacketCallback raw_callback_{ nullptr };
#endif
    void Run();

    std::string ip_port_;
    int backlog_;
    std::mutex conn_map_mutex_;
    bool create_server_{ false };
};

}  // namespace transport

}  // namespace tenon
