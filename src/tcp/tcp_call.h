#pragma once

#include "tcp/tcp_server.h"

namespace tenon {

namespace tcp {

class TcpCall {
public:
    TcpCall() {}
    ~TcpCall() {}
    int Init(
            int32_t thread_count,
            int32_t recv_timeout_sec,
            const char* ip,
            uint16_t port) {
        if (inited_) {
            return 1;
        }

        int res = tcp_server_.Init(
            thread_count,
            recv_timeout_sec,
            ip,
            port,
            std::bind(
                &TcpCall::Callback,
                this,
                std::placeholders::_1));
        if (res == 0) {
            inited_ = true;
        }

        return res;
    }

    void Start() {
        if (inited_) {
            tcp_server_.Start();
        }
    }

    void Stop() {
        if (inited_) {
            tcp_server_.Stop();
        }
    }

private:
    int32_t Callback(TcpConnection* con) {
        if (evhtp_unlikely(con->index < 4)) {
            return -1;
        }

        uint32_t* tid = (uint32_t*)con->recv_buff;
        std::string res;
//         if (evhtp_unlikely(task->TcpCall(
//                 con->recv_buff + 4,
//                 con->index - 4,
//                 &res) != task::kTaskSuccess)) {
//             std::string res("call task failed.");
//             tcp_server_.Send(con, res.c_str(), res.size());
//             // close tcp connect
//             return -1;
//         }

        if (evhtp_unlikely(!res.empty())) {
            tcp_server_.Send(con, res.c_str(), res.size());
        }

        return 0;
    }

    TcpServer tcp_server_;
    bool inited_{ false };

    DISALLOW_COPY_AND_ASSIGN(TcpCall);
};

};  // namespace tcp

};  // namespace tenon
