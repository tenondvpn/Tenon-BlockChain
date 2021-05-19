#include "stdafx.h"
#include "transport/udp/ev_udp_transport.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <functional>
#include <atomic>

#include "common/log.h"
#include "common/hash.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "transport/transport_utils.h"
#include "transport/multi_thread.h"
#include "transport/rudp/rudp.h"
#include "services/vpn_server/ev_loop_manager.h"

namespace tenon {

namespace transport {

static void Startup(void) {
#ifdef _WIN32
    struct WSAData wsa_data;
    int r = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    assert(r == 0);
#endif
}

static int32_t CreateUdpSocket(void) {
  int32_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
#ifdef _WIN32
  assert(sock != INVALID_SOCKET);
#else
  assert(sock >= 0);
#endif

#ifndef _WIN32
  {
    /* Allow reuse of the port. */
    int yes = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    assert(r == 0);
  }
#endif
  return sock;
}

static void SetNonblocking(int sockfd) {
    int flag = fcntl(sockfd, F_GETFL, 0);
    if (flag < 0) {
        return;
    }

    fcntl(sockfd, F_SETFL, flag | O_NONBLOCK);
}

EvUdpTransport::EvUdpTransport(
        uint32_t send_buffer_size,
        uint32_t recv_buffer_size)
        : send_buf_size_(send_buffer_size),
          recv_buf_size_(recv_buffer_size) {
    assert(send_buf_size_ > 0);
    assert(recv_buf_size_ > 0);
}

EvUdpTransport::~EvUdpTransport() {
    Stop();
}

int EvUdpTransport::Start(bool hold) {
    if (hold) {
        Run();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&EvUdpTransport::Run, this));
        run_thread_->detach();
    }
    return kTransportSuccess;
}

void EvUdpTransport::Stop() {
    destroy_ = true;
    if (loop_ != nullptr) {
        loop_ = nullptr;
    }
    TRANSPORT_ERROR("udp stoped!");
}

int EvUdpTransport::Init() {
    loop_ = vpn::EvLoopManager::Instance()->loop();
    if (loop_ == nullptr) {
        TRANSPORT_ERROR("create uv loop failed!");
        return kTransportError;
    }

    Startup();
    return kTransportSuccess;
}

user_ev_io_t* EvUdpTransport::CreateNewServer(
        const std::string& ip,
        uint16_t port,
        void(*ev_cb)(EV_P_ ev_io *w, int revents)) {
    user_ev_io_t* user_ev_io = (user_ev_io_t*)malloc(sizeof(user_ev_io_t));
    if (uv_ip4_addr(ip.c_str(), port, &user_ev_io->addr) != 0) {
        TRANSPORT_ERROR("create uv ipv4 addr failed!");
        free(user_ev_io);
        return nullptr;
    }

    Startup();
    user_ev_io->sock = CreateUdpSocket();
    SetNonblocking(user_ev_io->sock);
    setsockopt(
            user_ev_io->sock,
            SOL_SOCKET,
            SO_RCVBUF,
            (const char *)&recv_buf_size_,
            sizeof(recv_buf_size_));
    setsockopt(
            user_ev_io->sock,
            SOL_SOCKET,
            SO_SNDBUF,
            (const char *)&send_buf_size_,
            sizeof(send_buf_size_));

    memset(&user_ev_io->addr, 0, sizeof(user_ev_io->addr));
    user_ev_io->addr.sin_family = AF_INET;
    user_ev_io->addr.sin_port = htons(port);
    user_ev_io->addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(
            user_ev_io->sock,
            (struct sockaddr*) &user_ev_io->addr,
            sizeof(user_ev_io->addr)) != 0) {
        TRANSPORT_ERROR("create uv loop failed!");
        free(user_ev_io);
        return nullptr;
    }

    ev_io_init(&user_ev_io->io, ev_cb, user_ev_io->sock, EV_READ | EV_WRITE);
    ev_io_start(loop_, &user_ev_io->io);
    return user_ev_io;
}

void EvUdpTransport::Run() {
    while (true) {
        ev_loop(loop_, 0);
    }
}

int EvUdpTransport::SendToLocal(transport::protobuf::Header& message) {
    
    return kTransportSuccess;
}

int EvUdpTransport::SendKcpBuf(
		const std::string& ip,
		uint16_t port,
		const char* buf,
		uint32_t len) {
	return kTransportSuccess;
}

int EvUdpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        transport::protobuf::Header& proto) {
    return kTransportSuccess;
}

void EvUdpTransport::SetSocketOption() {
}

uint64_t EvUdpTransport::GetMessageHash(transport::protobuf::Header& message) {
    auto hash = common::Hash::Hash64(
           "udp" + message.src_node_id() + std::to_string(message.id()) + message.data());
    return hash;
}

}  // namespace transport

}  // namespace tenon
