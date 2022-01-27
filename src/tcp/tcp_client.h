#pragma once

#include "common/utils.h"
#include "tcp/tcp_util.h"

namespace tenon {

namespace tcp {

class TcpClient {
public:
    TcpClient();
    ~TcpClient();
    static void InitClientLoop();
    static void StopClientLoop();
    int Connect(
        const char* server_ip,
        uint16_t server_port,
        TcpClientEventCallback event_cb,
        TcpClientCallback tcp_callback);
    int Send(const char* data, int32_t len);
    int Reconnect();
    void Destroy();

    char* recv_buff{ nullptr };
    int32_t need_length{ 0 };
    int32_t index{ 0 };
    TcpClientEventCallback event_cb{ nullptr };
    TcpClientCallback callback{ nullptr };
    volatile bool closed{ false };

private:
    static struct event_base* base_;
    static std::thread* tcp_thread_;
    static bool loop_runed_;

    struct bufferevent* bev_{ nullptr };
    evutil_socket_t connect_fd_{ -1 };
    std::string server_ip_;
    uint16_t server_port_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(TcpClient);
};

};  // namespace tcp

};  // namespace tenon
