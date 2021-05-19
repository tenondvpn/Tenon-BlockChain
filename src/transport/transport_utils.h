#pragma once

#ifdef _WIN32
#include <Windows.h>
#include <WinSock2.h>
#else
#include <unistd.h>
#endif

#include "common/log.h"
#include "transport/proto/transport.pb.h"
#include "tnet/tcp_connection.h"

#define TRANSPORT_DEBUG(fmt, ...) TENON_DEBUG("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_INFO(fmt, ...) TENON_INFO("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_WARN(fmt, ...) TENON_WARN("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_ERROR(fmt, ...) TENON_ERROR("[transport]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace transport {

typedef std::function<void(
        tnet::TcpConnection* conn,
        char* message,
        uint32_t)> TcpRawPacketCallback;

enum TransportErrorCode {
    kTransportSuccess = 0,
    kTransportError = 1,
    kTransportTimeout = 2,
    kTransportClientSended = 3,
};

enum TransportPriority {
    kTransportPrioritySystem = 0,
    kTransportPriorityHighest = 1,
    kTransportPriorityHigh = 2,
    kTransportPriorityMiddle = 3,
    kTransportPriorityLow = 4,
    kTransportPriorityLowest = 5,
};

enum PacketTransportType {
    kOriginalUdp = 0,
    kTcp = 1,
    kKcpUdp = 2,
};

struct TransportHeader {
    uint16_t size;
    uint16_t type;
    uint32_t server_id;
    uint32_t msg_no;
    uint16_t context_id;
    uint16_t frag_len;
    uint32_t msg_index;
    uint32_t epoch;
    uint16_t fec_no;
    uint16_t fec_index;
    struct {
        uint8_t frag_no;
        uint8_t frag_sum;
        uint16_t mtu;
    } frag;
};

typedef std::function<void(protobuf::Header& message)> MessageProcessor;

static const uint32_t kMaxHops = 20u;
static const uint32_t kBroadcastMaxRelayTimes = 2u;
static const uint32_t kBroadcastMaxMessageCount = 1024u * 1024u;
static const uint32_t kUniqueMaxMessageCount = 1024u * 1024u;
static const uint32_t kKcpRecvWindowSize = 128u;
static const uint32_t kKcpSendWindowSize = 128u;
static const uint32_t kMsgPacketMagicNum = 345234223;
static const int32_t kTransportTxBignumVersionNum = 1;
static const int32_t kTransportVersionNum = 2;

inline void CloseSocket(int sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

}  // namespace transport

}  // namespace tenon
