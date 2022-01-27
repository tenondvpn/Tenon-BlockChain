#include "tcp/tcp_server.h"

static int32_t ParsePackage(tenon::tcp::TcpConnection* c, char* buf, size_t len) {
    int ret_len = 0;
    if (evhtp_unlikely(c->need_length <= 0)) {
        if (len <= tenon::tcp::kTcpHeaderLen) {
            return 0;
        }

//         tenon::tcp::TcpHeader* tcp_header = (tenon::tcp::TcpHeader*)buf;
        uint32_t* lens = (uint32_t*)buf;
        c->need_length = ntohl(lens[0]) - sizeof(uint32_t);
//         c->need_length = tcp_header->len;
        if (evhtp_unlikely(c->need_length >= (int32_t)tenon::tcp::kReceiveBuffMaxSize ||
                c->need_length <= 0)) {
            return -1;
        }

        buf += tenon::tcp::kTcpHeaderLen;
        len -= tenon::tcp::kTcpHeaderLen;
        ret_len = tenon::tcp::kTcpHeaderLen;
    }

    if (evhtp_unlikely((int32_t)len >= c->need_length)) {
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
    tenon::tcp::TcpConnection* c = (tenon::tcp::TcpConnection*)arg;
    evbuffer* input = bufferevent_get_input(bev);
    while (true) {
        auto avail = evbuffer_get_length(input);
        if (evhtp_unlikely(avail == 0)) {
            return;
        }

        char* buf = (char*)evbuffer_pullup(bufferevent_get_input(bev), avail);
        if (evhtp_unlikely(buf == nullptr)) {
            FreeTcpConnection(c);
            return;
        }

        int32_t read_len = ParsePackage(c, buf, avail);
        if (evhtp_unlikely(read_len == -1)) {
            FreeTcpConnection(c);
            return;
        }

        if (evhtp_unlikely(c->need_length == 0 && c->index > 0)) {
            // call back
            if (c->callback != nullptr) {
                int32_t res = c->callback(c);
                if (res < 0) {
                    FreeTcpConnection(c);
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

static void WriteCallback(struct bufferevent *bev, void *arg) {
    if (evhtp_unlikely(arg == NULL)) {
        bufferevent_free(bev);
    }
}

static void EventCallback(struct bufferevent *bev, short events, void *arg) {
    tenon::tcp::TcpConnection* c = (tenon::tcp::TcpConnection*)arg;
    if (events & BEV_EVENT_EOF) {
    } else if (events & BEV_EVENT_ERROR) {
        TENON_ERROR("Got an error on the connection: %s", strerror(errno));
    }

    TENON_INFO("close socket called: %s:%d", c->client_ip, c->client_port);
    if (c->recv_buff != nullptr) {
        FreeTcpConnection(c);
    }

    bufferevent_free(bev);
}

static void TcpRunInThread(evthr_t * thr, void * arg, void * shared) {
    tenon::tcp::TcpConnection * connection = (tenon::tcp::TcpConnection*)arg;
    connection->evbase = evthr_get_base(thr);
    connection->thread = thr;
    connection->bev = bufferevent_socket_new(connection->evbase, connection->fd, 0);
    struct timeval * c_recv_timeo;
    struct timeval * c_send_timeo;
    if (connection->recv_timeo.tv_sec || connection->recv_timeo.tv_usec) {
        c_recv_timeo = &connection->recv_timeo;
    } else {
        c_recv_timeo = NULL;
    }

    if (connection->send_timeo.tv_sec || connection->send_timeo.tv_usec) {
        c_send_timeo = &connection->send_timeo;
    } else {
        c_send_timeo = NULL;
    }

    bufferevent_set_timeouts(connection->bev, c_recv_timeo, c_send_timeo);
    bufferevent_setcb(connection->bev,
        ReadCallback,
        WriteCallback,
        EventCallback,
        connection);
    bufferevent_enable(connection->bev, EV_READ);
}

static void ListenerCallback(
        struct evconnlistener *listener,
        evutil_socket_t fd,
        struct sockaddr *sa,
        int socklen,
        void *user_data) {
    tenon::tcp::TcpServer* tcp_svr = (tenon::tcp::TcpServer*)user_data;
    tenon::tcp::TcpConnection* tcp_conn = new tenon::tcp::TcpConnection();
    tcp_conn->fd = fd;
    tcp_conn->need_length = -1;
    tcp_conn->recv_buff = new char[tenon::tcp::kReceiveBuffMaxSize];
    tcp_conn->callback = tcp_svr->tcp_callback();
    tcp_conn->recv_timeo.tv_sec = tcp_svr->recv_timeout_milli() / 1000;
    tcp_conn->recv_timeo.tv_usec = (tcp_svr->recv_timeout_milli() % 1000) * 1000;
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    inet_ntop(AF_INET, (const void*)&sin->sin_addr, tcp_conn->client_ip, sizeof(tcp_conn->client_ip));
    tcp_conn->client_port = htons(sin->sin_port);
    if (tcp_svr->pool() != NULL) {
        if (evthr_pool_defer(tcp_svr->pool(), TcpRunInThread, (void*)tcp_conn) != EVTHR_RES_OK) {
            evutil_closesocket(fd);
            delete tcp_conn;
            return;
        }

        return;
    }

    struct event_base *base = (struct event_base*)user_data;
    struct bufferevent *bev;
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stderr, "Error constructing bufferevent!");
        event_base_loopbreak(base);
        return;
    }

    bufferevent_setcb(bev, ReadCallback, WriteCallback, EventCallback, NULL);
    bufferevent_enable(bev, EV_READ);
}

static int tcp_serv_setsockopts(evutil_socket_t sock) {
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on)) == -1) {
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1) {
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on)) == -1) {
        if (errno != EOPNOTSUPP) {
            TENON_ERROR("SO_REUSEPORT error");
            return -1;
        }

        TENON_WARN("SO_REUSEPORT NOT SUPPORTED");
    }

    return 0;
}

namespace tenon {

namespace tcp {

TcpServer::TcpServer() {}

TcpServer::~TcpServer() {
    if (pool_ != nullptr) {
        evthr_pool_free(pool_);
    }

    if (tcp_thread_ != nullptr) {
        tcp_thread_->join();
        delete tcp_thread_;
    }

    if (listener_ != nullptr) {
        evconnlistener_free(listener_);
    }

    if (signal_event_ != nullptr) {
        event_free(signal_event_);
    }

    if (base_ != nullptr) {
        event_base_free(base_);
    }

    if (listen_fd_ != -1) {
        evutil_closesocket(listen_fd_);
        listen_fd_ = -1;
    }
}

int TcpServer::Init(
        int32_t thread_count,
        int32_t recv_timeout_milli,
        const char* ip,
        uint16_t port,
        TcpServerCallback tcp_callback) {
    tcp_callback_ = tcp_callback;
    recv_timeout_milli_ = recv_timeout_milli;
    struct sockaddr_in sin = { 0 };
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    base_ = event_base_new();
    if (!base_) {
        TENON_ERROR("Could not initialize libevent!");
        return 1;
    }

    struct timeval tv;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip);
    sin.sin_port = htons(port);
    struct sockaddr* sa = (struct sockaddr *)&sin;
    listen_fd_ = -1;
    if ((listen_fd_ = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
        TENON_ERROR("couldn't create socket");
        return 1;
    }

    evutil_make_socket_closeonexec(listen_fd_);
    evutil_make_socket_nonblocking(listen_fd_);
    tcp_serv_setsockopts(listen_fd_);
    if (bind(listen_fd_, sa, sizeof(struct sockaddr_in)) == -1) {
        evutil_closesocket(listen_fd_);
        listen_fd_ = -1;
        return 1;
    }

    listener_ = evconnlistener_new(
        base_,
        ListenerCallback,
        (void *)this,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
        -1,
        listen_fd_);
    if (!listener_) {
        TENON_ERROR("Could not create a listener!");
        evutil_closesocket(listen_fd_);
        listen_fd_ = -1;
        return 1;
    }

    pool_ = evthr_pool_wexit_new(thread_count, nullptr, nullptr, nullptr);
    if (pool_ == nullptr) {
        evutil_closesocket(listen_fd_);
        listen_fd_ = -1;
        return 1;
    }

    evthr_pool_start(pool_);
    TENON_INFO("create tcp server success: %s:%d", ip, port);
    return 0;
}

void TcpServer::Start() {
    tcp_thread_ = new std::thread(std::bind(&TcpServer::Run, this));
}

void TcpServer::Run() {
    event_base_dispatch(base_);
}

void TcpServer::Stop() {
    if (pool_ != nullptr) {
        evthr_pool_stop(pool_);

    }

    struct timeval delay = { 0, 100000 };
    int res = event_base_loopexit(base_, NULL);
    TENON_INFO("exit: %d, got: %d\n", res, event_base_got_exit(base_));
}

int TcpServer::Send(TcpConnection* con, const char* data, int32_t len) {
    return bufferevent_write(con->bev, data, len);
}

};  // namespace tcp

};  // namespace tenon
