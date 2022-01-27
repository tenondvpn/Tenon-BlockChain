#include "http/http_server.h"

#include <signal.h>
#include <functional>
#include <map>

#include "common/string_utils.h"

namespace tenon {

namespace http {

static HttpServer* http_server = nullptr;

static void HttpReqCallback(evhtp_request_t* req, void* data) {
//     auto b_time_1 = common::GetTimestampUs();
    const char* tid = evhtp_kv_find(req->uri->query, kHttpParamTaskId.c_str());
    if (tid == nullptr) {
        std::string res("no tid param\n");
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    uint64_t task_id = 0;
    if (!common::StringUtil::ToUint64(std::string(tid), &task_id)) {
        std::string res("tid not integer\n");
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }


    std::string res;
    if (task->HttpCall(req->uri->query, req->buffer_out) != task::kTaskSuccess) {
        std::string res("call task failed.");
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    evhtp_send_reply(req, EVHTP_RES_OK);
}

HttpServer::HttpServer() {
    http_server = this;
}

HttpServer::~HttpServer() {}

HttpServer* HttpServer::Instance() {
    static HttpServer ins;
    return &ins;
}

int32_t HttpServer::Init(
        task::TaskManager* task_mgr,
        const char* ip,
        uint16_t port,
        int32_t thread_count) {
    evbase_ = event_base_new();
    if (evbase_ == nullptr) {
        return kHttpError;
    }

    htp_ = evhtp_new(evbase_, NULL);
    if (htp_ == nullptr) {
        return kHttpError;
    }

    evhtp_set_cb(
        htp_,
        "/dags",
        HttpReqCallback,
        NULL);
    evhtp_use_threads_wexit(htp_, NULL, NULL, thread_count, NULL);
    evhtp_bind_socket(htp_, ip, port, 1024);
    TENON_INFO("start http server: %s: %d", ip, port);
    return kHttpSuccess;
}

int32_t HttpServer::Start() {
    if (htp_ == nullptr) {
        return kHttpError;
    }

    http_thread_ = new std::thread(std::bind(&HttpServer::RunHttpServer, this));
    http_thread_->detach();
    return kHttpSuccess;
}

void HttpServer::RunHttpServer() {
    event_base_loop(evbase_, 0);
}

int32_t HttpServer::Stop() {
    if (evbase_ != nullptr) {
        event_base_loopexit(evbase_, NULL);
    }

    if (http_thread_ != nullptr) {
        delete http_thread_;
        http_thread_ = nullptr;
    }

    if (ev_sigint_ != nullptr) {
        evhtp_safe_free(ev_sigint_, event_free);
    }

    if (htp_ != nullptr) {
        evhtp_unbind_socket(htp_);
        evhtp_safe_free(htp_, evhtp_free);
    }

    if (evbase_ != nullptr) {
        evhtp_safe_free(evbase_, event_base_free);
    }

    return kHttpSuccess;
}

};  // namespace tenon

};  // namespace tenon
