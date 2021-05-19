#pragma once

#include <string>
#include <memory>
#include <thread>

#include "uv/uv.h"

#include "common/log.h"
#include "transport/transport.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace transport {

typedef void(*UdpServerReceiveCallback)(
        uv_udp_t* handle,
        ssize_t nread,
        const uv_buf_t* rcvbuf,
        const struct sockaddr* addr,
        unsigned flags);
class TestTransport : public Transport {
public:
    TestTransport() {}
    virtual ~TestTransport() {}
    virtual int Init() {
        return kTransportSuccess;
    }

    virtual int Start(bool hold) {
        return kTransportSuccess;
    }

    virtual void Stop() {}
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message) {
        return kTransportSuccess;
    }

    virtual int SendToLocal(transport::protobuf::Header& message) {
        return kTransportSuccess;
    }

    virtual int GetSocket() {
        return 0;
    }

    virtual void FreeConnection(const std::string& ip, uint16_t port) {}

private:
};

}  // namespace transport

}  // namespace tenon
