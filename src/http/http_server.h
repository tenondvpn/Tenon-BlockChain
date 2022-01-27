#pragma once

#include <evhtp/evhtp.h>
#include <evhtp/internal.h>

#include "http/http_utils.h"

namespace tenon {

namespace http {

class HttpServer {
public:
    static HttpServer* Instance();
    int32_t Init(const char* ip, uint16_t port, int32_t thread_count);
    int32_t Start();
    int32_t Stop();

private:
    HttpServer();
    ~HttpServer();
    void RunHttpServer();

    evbase_t* evbase_{ nullptr };
    evhtp_t* htp_{ nullptr };
    std::thread* http_thread_{ nullptr };
    struct event* ev_sigint_ {nullptr};

    DISALLOW_COPY_AND_ASSIGN(HttpServer);
};

};  // namespace tenon

};  // namespace tenon
