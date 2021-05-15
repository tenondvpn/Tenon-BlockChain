#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <memory>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ev.h"

#include "common/log.h"
#include "transport/transport.h"

typedef void(*ev_callback)(EV_P_ ev_io *w, int revents);
struct user_ev_io_t {
    ev_io io;
    struct sockaddr_in addr;
    int sock;
};

namespace lego {

namespace transport {

class EvUdpTransport : public Transport {
public:
    EvUdpTransport(
            uint32_t send_buffer_size,
            uint32_t recv_buffer_size);
    virtual ~EvUdpTransport();
    virtual int Init();
    virtual int Start(bool hold);
    virtual void Stop();
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message);
    virtual int SendToLocal(transport::protobuf::Header& message);
    virtual int GetSocket() {
        return 0;
    }
    virtual void FreeConnection(const std::string& ip, uint16_t port) {}

	int SendKcpBuf(
			const std::string& ip,
			uint16_t port,
			const char* buf,
			uint32_t len);
    user_ev_io_t* CreateNewServer(const std::string& ip, uint16_t port, void(*ev_cb)(EV_P_ ev_io *w, int revents));

private:
    void Run();
    void SetSocketOption();
    uint64_t GetMessageHash(transport::protobuf::Header& message);

    static const uint32_t kDefaultTtl = 99u;

    struct ev_loop *loop_{ nullptr };
    uint32_t send_buf_size_{ 0 };
    uint32_t recv_buf_size_{ 0 };
    std::shared_ptr<std::thread> run_thread_{ nullptr };
    bool destroy_{ false };

    DISALLOW_COPY_AND_ASSIGN(EvUdpTransport);
};

typedef std::shared_ptr<EvUdpTransport> EvUdpTransportPtr;

}  // namespace transport

}  // namespace lego
