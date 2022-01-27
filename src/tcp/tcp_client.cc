#include "tcp/tcp_client.h"

#include <mutex>

#include <sys/socket.h>
#include <netinet/tcp.h>

static int32_t ParsePackage(dag::tcp::TcpClient* c, char* buf, size_t len) {
    int ret_len = 0;
    if (c->need_length <= 0) {
        if (len <= dag::tcp::kTcpHeaderLen) {
            return 0;
        }

        uint32_t* lens = (uint32_t*)buf;
        c->need_length = ntohl(lens[0]) - sizeof(uint32_t);
        if (evhtp_unlikely(c->need_length >= (int32_t)dag::tcp::kReceiveBuffMaxSize ||
                c->need_length <= 0)) {
            return -1;
        }

        buf += dag::tcp::kTcpHeaderLen;
        len -= dag::tcp::kTcpHeaderLen;
        ret_len = dag::tcp::kTcpHeaderLen;
    }

    if ((int32_t)len >= c->need_length) {
        memcpy(c->recv_buff + c->index, buf, c->need_length);
        ret_len += c->need_length;
        c->index += c->need_length;
        c->need_length = 0;
    } else {
        memcpy(c->recv_buff + c->index, buf, len);
        ret_len += len;
        c->need_length -= len;
        c->index += len;
    }

    return ret_len;
}

static void ReadCallback(struct bufferevent *bev, void *arg) {
    dag::tcp::TcpClient* c = (dag::tcp::TcpClient*)arg;
    evbuffer* input = bufferevent_get_input(bev);
    while (true) {
        auto avail = evbuffer_get_length(input);
        if (evhtp_unlikely(avail == 0)) {
            return;
        }

        char* buf = (char*)evbuffer_pullup(bufferevent_get_input(bev), avail);
        if (evhtp_unlikely(buf == nullptr)) {
            // TODO connect error close
            return;
        }

        int32_t read_len = ParsePackage(c, buf, avail);
        if (evhtp_unlikely(read_len == -1)) {
            // TODO connect error close
            return;
        }

        if (evhtp_unlikely(c->need_length == 0 && c->index > 0)) {
            // call back
            if (c->callback != nullptr) {
                int32_t res = c->callback(c->recv_buff, c->index);
                if (res < 0) {
                    // TODO connect error close
                    return;
                }
            }

            c->index = 0;
        }

        evbuffer_drain(bufferevent_get_input(bev), read_len);
        if (evhtp_unlikely(read_len == 0 || read_len == (int32_t)avail)) {
            break;
        }
    }
}

static void WriteCb(struct bufferevent *bev, void *arg) {
}

static void EventCb(struct bufferevent *bev, short events, void * arg) {
    dag::tcp::TcpClient* c = (dag::tcp::TcpClient*)arg;
    if (events & BEV_EVENT_EOF) {
        TENON_INFO("connection closed");
    } else if (events & BEV_EVENT_ERROR) {
        TENON_ERROR("some other error\n");
    } else if (events & BEV_EVENT_CONNECTED) {
        evutil_socket_t fd = bufferevent_getfd(bev);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        TENON_INFO("connected");
        c->closed = false;
        if (c->event_cb != nullptr) {
            c->event_cb(dag::tcp::kConnected);
        }
        return;
    }

    c->closed = true;
    if (c->event_cb != nullptr) {
        c->event_cb(dag::tcp::kClosed);
    }

    TENON_INFO("connection closed");
}

namespace tenon {

namespace tcp {

TcpClient::TcpClient() {}

TcpClient::~TcpClient() {
    if (recv_buff != nullptr) {
        delete[] recv_buff;
        recv_buff = nullptr;
    }

    if (bev_ != nullptr) {
        bufferevent_free(bev_);
        bev_ = nullptr;
    }
}

struct event_base* TcpClient::base_ = nullptr;
std::thread* TcpClient::tcp_thread_ = nullptr;
bool TcpClient::loop_runed_ = false;
static std::mutex loop_mutex;

static void RunClientLoop(struct event_base* base) {
    while (event_base_dispatch(base) != 0 && !common::global_stop) {
        TENON_WARN("event base dispatch error.");
        usleep(1000000);
    }
}

void TcpClient::InitClientLoop() {
    std::lock_guard<std::mutex> guard(loop_mutex);
    if (loop_runed_) {
        return;
    }

    base_ = event_base_new();
    tcp_thread_ = new std::thread(RunClientLoop, base_);
    loop_runed_ = true;
}

void TcpClient::StopClientLoop() {
    std::lock_guard<std::mutex> guard(loop_mutex);
    if (!loop_runed_) {
        return;
    }

    event_base_loopbreak(base_);
    if (tcp_thread_ != nullptr) {
        tcp_thread_->join();
        delete tcp_thread_;
        tcp_thread_ = nullptr;
    }

    loop_runed_ = false;
}

int TcpClient::Connect(
        const char* server_ip,
        uint16_t server_port,
        TcpClientEventCallback evcb,
        TcpClientCallback tcp_callback) {
    recv_buff = new char[kReceiveBuffMaxSize];
    callback = tcp_callback;
    event_cb = evcb;
    server_ip_ = server_ip;
    server_port_ = server_port;
    return Reconnect();
}

int TcpClient::Reconnect() {
    closed = true;
    if (base_ == nullptr) {
        return 1;
    }

    if (bev_ != nullptr) {
        bufferevent_free(bev_);
        bev_ = nullptr;
    }

    bev_ = bufferevent_socket_new(base_, connect_fd_, BEV_OPT_CLOSE_ON_FREE);
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(server_port_);
    inet_pton(AF_INET, server_ip_.c_str(), &serv.sin_addr.s_addr);
    bufferevent_setcb(bev_, ReadCallback, WriteCb, EventCb, this);
    bufferevent_enable(bev_, EV_READ);
    bufferevent_socket_connect(bev_, (struct sockaddr*)&serv, sizeof(serv));
    int32_t wait_times = 0;
    usleep(100000);
    while (closed && wait_times++ <= 30) {
        TENON_WARN("waiting connect to: %s:%d", server_ip_.c_str(), server_port_);
        usleep(100000);
    }

    return closed ? 1 : 0;
}

void TcpClient::Destroy() {
//     bufferevent_setcb(bev_, nullptr, nullptr, nullptr, this);
//     bufferevent_disable(bev_, EV_READ | EV_WRITE);
    callback = nullptr;
    event_cb = nullptr;
    if (bev_ != nullptr) {
        bufferevent_free(bev_);
        bev_ = nullptr;
    }
}

int TcpClient::Send(const char* data, int32_t len) {
    return bufferevent_write(bev_, data, len);
}

};  // namespace tcp

};  // namespace tenon
