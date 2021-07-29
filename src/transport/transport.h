#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"

namespace tenon {

namespace transport {

class Transport {
public:
    virtual int Init() = 0;
    virtual int Start(bool hold) = 0;
    virtual void Stop() = 0;
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            const transport::protobuf::Header& message) = 0;
    virtual int SendToLocal(const transport::protobuf::Header& message) = 0;
    virtual int GetSocket() = 0;
    virtual void FreeConnection(const std::string& ip, uint16_t port) = 0;

protected:
    Transport() {}
    virtual ~Transport() {}

private:

    DISALLOW_COPY_AND_ASSIGN(Transport);
};

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace transport

}  // namespace tenon
