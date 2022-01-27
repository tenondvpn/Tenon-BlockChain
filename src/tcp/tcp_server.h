#pragma once

#include "common/utils.h"
#include "tcp/tcp_util.h"

namespace tenon {

namespace tcp {

class TcpServer {
public:
    TcpServer();
    ~TcpServer();
    int Init(
        int32_t thread_count,
        int32_t recv_timeout_sec,
        const char* ip,
        uint16_t port,
        TcpServerCallback tcp_callback);
    void Start();
    void Stop();
    int Send(TcpConnection* con, const char* data, int32_t len);
    evthr_pool_t* pool() {
        return pool_;
    }

    TcpServerCallback tcp_callback() {
        return tcp_callback_;
    }

    int32_t recv_timeout_milli() {
        return recv_timeout_milli_;
    }

private:
    void Run();

    evthr_pool_t* pool_{ nullptr };
    struct event_base* base_{ nullptr };
    struct evconnlistener* listener_{ nullptr };
    struct event* signal_event_ { nullptr };
    TcpServerCallback tcp_callback_{ nullptr };
    std::thread* tcp_thread_{ nullptr };
    int32_t recv_timeout_milli_{ 0 };
    evutil_socket_t listen_fd_{ -1 };

    DISALLOW_COPY_AND_ASSIGN(TcpServer);
};

};  // namespace tcp

};  // namespace tenon
