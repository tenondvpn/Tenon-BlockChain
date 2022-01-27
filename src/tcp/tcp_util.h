#pragma once

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

#include <functional>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp/thread.h>
#include <evhtp/internal.h>

#include "common/utils.h"

namespace tenon {

namespace tcp {

#define EVHTP_CONN_FLAG_ERROR         (1 << 1)
#define EVHTP_CONN_FLAG_OWNER         (1 << 2) /**< set to 1 if this structure owns the bufferevent */
#define EVHTP_CONN_FLAG_VHOST_VIA_SNI (1 << 3) /**< set to 1 if the vhost was found via SSL SNI */
#define EVHTP_CONN_FLAG_PAUSED        (1 << 4) /**< this connection has been marked as paused */
#define EVHTP_CONN_FLAG_CONNECTED     (1 << 5) /**< client specific - set after successful connection */
#define EVHTP_CONN_FLAG_WAITING       (1 << 6) /**< used to make sure resuming  happens AFTER sending a reply */
#define EVHTP_CONN_FLAG_FREE_CONN     (1 << 7)
#define EVHTP_CONN_FLAG_KEEPALIVE     (1 << 8) /**< set to 1 after the first request has been processed and the connection is kept open */

static const uint32_t kReceiveBuffMaxSize = 10u * 1024u * 1024u;
struct TcpConnection;
typedef std::function<int32_t(TcpConnection* con)> TcpServerCallback;
typedef std::function<int32_t(const char* data, int32_t len)> TcpClientCallback;
typedef std::function<int32_t(int32_t event)> TcpClientEventCallback;

struct TcpHeader {
    uint32_t len;
};

enum ClientEvent : int32_t {
    kConnected = 0,
    kClosed = 1,
};

static const uint32_t kTcpHeaderLen = sizeof(TcpHeader);

struct TcpConnection {
    struct event_base* evbase{ nullptr };
    struct bufferevent* bev{ nullptr };
    evthr_t* thread{ nullptr };
    evutil_socket_t fd;
    struct timeval recv_timeo;
    struct timeval send_timeo;
    uint16_t flags{ 0 };
    struct event* resume_ev { nullptr };
    char* recv_buff{ nullptr };
    int32_t need_length{ 0 };
    int32_t index{ 0 };
    TcpServerCallback callback{ nullptr };
    uint32_t tid{ 0 };
    char client_ip[16];
    uint16_t client_port{ 0 };
};

inline static void FreeTcpConnection(TcpConnection* c) {
    delete c->recv_buff;
    c->recv_buff = nullptr;
    delete c;
}

};  // namespace tcp

};  // namespace tenon
