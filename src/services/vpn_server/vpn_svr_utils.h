#pragma once

#include <memory>
#include <deque>

#include "kcp/ikcp.h"
#include "common/utils.h"
#include "common/log.h"
#include "transport/udp/udp_transport.h"
#include "transport/udp/ev_udp_transport.h"
#include "transport/tcp/msg_packet.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "openfec/lib_common/of_openfec_api.h"

    of_status_t	of_create_codec_instance(of_session_t**	ses,
        of_codec_id_t		codec_id,
        of_codec_type_t	codec_type,
        UINT32		verbosity);
    of_status_t	of_set_fec_parameters(of_session_t* ses, of_parameters_t*	params);
    of_status_t	of_decode_with_new_symbol(of_session_t*	ses,
        void* const	new_symbol_buf,
        UINT32		new_symbol_esi);
    of_status_t	of_build_repair_symbol(
            of_session_t*	ses,
            void*	encoding_symbols_tab[],
            UINT32	esi_of_symbol_to_build);
    of_status_t	of_get_source_symbols_tab(of_session_t*	ses,
        void*		source_symbols_tab[]);

#ifdef __cplusplus
}
#endif

#define VPNSVR_DEBUG(fmt, ...) TENON_DEBUG("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_INFO(fmt, ...) TENON_INFO("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_WARN(fmt, ...) TENON_WARN("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_ERROR(fmt, ...) TENON_WARN("[vpn_svr]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace vpn {

class EndPoint;
class FecOpenFecDecoder;
class FecOpenFecEncoder;

enum VpnSvrErrorCode {
    kVpnsvrSuccess = 0,
    kVpnsvrError = 1,
};

enum RouteNodeMessageType {
    kHeartbeatRequest = 0,
    kHeartbeatResponse = 1,
    kStreamRequest = 2,
    kStreamResponse = 3,
    kStreamStop = 4,
    kStreamAck = 5,
    kStreamNakRequest = 6,
    kStreamNakResponse = 7,
    kStreamTimeoutNakRequest = 8,
    kStreamTimeoutNakResponse = 9,
    kFecStream = 10,
};

enum VpnMessageType {
    kRouteServerClosed = 1721,
    kRemoteServerClosed = 1722,
};

struct UdpUserData {
    uv_udp_t* uv_udp;
    user_ev_io_t* user_ev_io;
    char ip[32];
    uint16_t port;
    uint32_t id;
    FecOpenFecEncoder* fec_encoder;
    FecOpenFecDecoder* fec_decoder;
};

struct VlanNodeInfo {
    VlanNodeInfo(
            const std::string& in_ip,
            uint16_t in_port,
            const std::string& in_dht_key,
            const std::string& in_public_key,
            uint32_t in_timeout_times)
            : ip(in_ip),
              port(in_port),
              dht_key(in_dht_key),
              public_key(in_public_key),
              timeout_times(in_timeout_times) {}
    std::string ip;
    uint16_t port;
    std::string dht_key;
    std::string public_key;
    uint32_t timeout_times;
};

struct TcpRelayHead {
    union 
    {
        uint32_t client_id;
        uint32_t stream_len;
    };
    uint16_t server_id;
    uint16_t msg_id;
};

struct TnetWithRelayHead {
    TnetWithRelayHead(uint32_t len, uint32_t type) : header(len, type) {}
    transport::PacketHeader header;
    TcpRelayHead relay_head;
};

typedef std::shared_ptr<VlanNodeInfo> VlanNodeInfoPtr;

static const uint32_t kSpesialNumForUdp = 3987654321u;
static const uint32_t kCheckNakTimeoutMilli = 300u;

static const uint32_t kSymbolSize = 1440;
static const uint32_t kDefaultK = 16;
static const double kCodeRate = 0.667;
static const double kLossRate = 0.30;
static const uint32_t kUdpForHoleMaxCount = 60u;

}  // namespace vpn

}  // namespace tenon
