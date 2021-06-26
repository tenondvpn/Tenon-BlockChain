#include "stdafx.h"
#include "services/vpn_server/vpn_server.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#endif
#include <libcork/core.h>
#include  <netinet/in.h>
#include <netinet/tcp.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "ssr/netutils.h"
#include "ssr/crypto.h"
#include "ssr/utils.h"
#include "ssr/acl.h"
#include "ssr/plugin.h"
#include "ssr/winsock.h"
#include "ssr/stream.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

#ifndef MAX_FRAG
#define MAX_FRAG 1
#endif

#ifndef CONNECT_IN_PROGRESS
#define CONNECT_IN_PROGRESS 115
#endif // !CONNECT_IN_PROGRESS


#ifdef USE_NFCONNTRACK_TOS

#ifndef MARK_MAX_PACKET
#define MARK_MAX_PACKET 10
#endif

#ifndef MARK_MASK_PREFIX
#define MARK_MASK_PREFIX 0xDC00
#endif

#endif

#ifdef __cplusplus
}
#endif

#include "common/string_utils.h"
#include "common/encode.h"
#include "common/country_code.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/split.h"
#include "common/user_property_key_define.h"
#include "contract/contract_utils.h"
#include "client/trans_client.h"
#include "client/proto/client_proto.h"
#include "db/db_utils.h"
#include "security/crypto_utils.h"
#include "services/account_with_secret.h"
#include "sync/key_value_sync.h"
#include "transport/synchro_wait.h"
#include "network/universal_manager.h"
#include "network/route.h"
#include "network/dht_manager.h"
#include "dht/base_dht.h"
#include "db/db.h"
#include "block/proto/block.pb.h"
#include "block/proto/block_proto.h"
#include "contract/proto/contract.pb.h"
#include "contract/proto/contract_proto.h"
#include "bft/proto/bft.pb.h"
#include "bft/proto/bft_proto.h"
#include "init/update_vpn_init.h"
#include "services/vpn_server/ev_loop_manager.h"
#include "services/vpn_server/fec_openfec_decoder.h"
#include "services/vpn_server/fec_openfec_encoder.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"
#include "services/vpn_server/tcp_relay_client.h"
#include "services/bandwidth_manager.h"
#include "statistics/statistics.h"

using namespace tenon;

static void AcceptCallback(EV_P_ ev_io *w, int revents);
static void ServerSendCallback(EV_P_ ev_io *w, int revents);
static void ServerRecvCallback(EV_P_ ev_io *w, int revents);
static void RemoteRecvCallback(EV_P_ ev_io *w, int revents);
static void RemoteSendCallback(EV_P_ ev_io *w, int revents);
static void ServerTimeoutCallback(EV_P_ ev_timer *watcher, int revents);

static remote_t *NewRemote(int fd);
static server_t *NewServer(int fd, listen_ctx_t *listener);
static remote_t *ConnectToRemote(EV_P_ struct addrinfo *res, server_t *server);

static void FreeRemote(remote_t *remote);
static void CloseAndFreeRemote(EV_P_ remote_t *remote);
static void FreeServer(server_t *server);
static void CloseAndFreeServer(EV_P_ server_t *server);
static void ResolvCallback(struct sockaddr *addr, void *data);
static void ResolvFreeCallback(void *data);

static int acl = 0;
static int mode = TCP_ONLY;
static int ipv6first = 0;
static int fast_open = 1;
static int no_delay = 1;
static int ret_val = 0;
static const uint32_t kBandwidthPeriod = 120u * 1000u * 1000u;
static const uint64_t kVipCheckPeriod = 180llu * 1000llu * 1000llu;
static const uint64_t kVpnClientTimeout = 300llu * 1000llu * 1000llu;
static const std::string kCheckVersionAccount = common::Encode::HexDecode(
    "e8a1ceb6b807a98a20e3aa10aa2199e47cbbed08c2540bd48aa3e1e72ba6bd99");
static std::unordered_map<uint64_t, server_t*> global_server_map;
static std::unordered_map<uint64_t, remote_t*> global_remote_map;
static std::unordered_set<uint64_t> global_removed_server_set;
static uint64_t global_prev_check_timestamp = 0;
static const uint32_t kRecvBufferLen = 1024 * 1024;
static char kcp_recv_buffer[kRecvBufferLen + 1];
static char udp_send_buffer[kRecvBufferLen + 1];
static std::mutex global_server_mutex;
static uint32_t global_server_passed_bandwidth = 0;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
int use_syslog = 0;

#ifndef __MINGW32__
ev_timer stat_update_watcher;
#endif

static const uint32_t kMaxConnectAccount = 1024u;  // single server just 1024 user

static void FreeConnections(struct ev_loop *loop, struct cork_dllist* connections) {
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(connections, curr, next) {
        server_t *server = (server_t*)cork_container_of(curr, server_t, entries);
        remote_t *remote = (remote_t*)server->remote;
        CloseAndFreeServer(loop, server);
        CloseAndFreeRemote(loop, remote);
    }
}

static char * GetPeerName(int fd) {
    static char peer_name[INET6_ADDRSTRLEN] = { 0 };
    struct sockaddr_storage addr;
    socklen_t len = sizeof(struct sockaddr_storage);
    memset(&addr, 0, len);
    memset(peer_name, 0, INET6_ADDRSTRLEN);
    int err = getpeername(fd, (struct sockaddr *)&addr, &len);
    if (err == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &s->sin_addr, peer_name, INET_ADDRSTRLEN);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &s->sin6_addr, peer_name, INET6_ADDRSTRLEN);
        }
    } else {
        return NULL;
    }
    return peer_name;
}

static void StopServer(EV_P_ server_t *server) {
    server->stage = STAGE_STOP;
}

static void ReportAddr(int fd, const char *info) {
    char *peer_name;
    peer_name = GetPeerName(fd);
    if (peer_name != NULL) {
        LOGE("failed to handshake with %s: %s", peer_name, info);
    }
}

int SetFastopen(int fd) {
    int s = 0;
#ifdef TCP_FASTOPEN
    if (fast_open) {
#if defined(__APPLE__) || defined(__MINGW32__)
        int opt = 1;
#else
        int opt = 5;
#endif
        s = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

        if (s == -1) {
            if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
                LOGE("fast open is not supported on this platform");
                fast_open = 0;
            } else {
                ERROR("setsockopt");
            }
        }
    }
#endif
    return s;
}

#ifndef __MINGW32__
int SetNonblocking(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

int CreateAndBind(const char *host, const char *port, int mptcp) {
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    result = NULL;

    s = getaddrinfo(host, port, &hints, &result);

    if (s != 0) {
        LOGE("failed to resolve server name %s", host);
        return -1;
    }

    if (result == NULL) {
        LOGE("Cannot bind");
        return -1;
    }

    rp = result;

    /*
        * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
        * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
        * return a list of addresses to listen on, but it is impossible to listen on
        * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
        */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int opt = host ? 1 : 0;
            setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (mptcp == 1) {
            int i = 0;
            while ((mptcp = mptcp_enabled_values[i]) > 0) {
                int err = setsockopt(listen_sock, IPPROTO_TCP, mptcp, &opt, sizeof(opt));
                if (err != -1) {
                    break;
                }
                i++;
            }
            if (mptcp == 0) {
                ERROR("failed to enable multipath TCP");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
            return -1;
        }

        close(listen_sock);
        listen_sock = -1;
    }
    freeaddrinfo(result);
    return listen_sock;
}

static remote_t * VlanServerConnectToRoute(EV_P_ struct addrinfo *des_addr) {
    int sockfd;
    sockfd = socket(des_addr->ai_family, des_addr->ai_socktype, des_addr->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (SetNonblocking(sockfd) == -1)
        ERROR("SetNonblocking");

#ifdef SET_INTERFACE
    if (iface) {
        if (setinterface(sockfd, iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            return NULL;
    }
}
#endif

    remote_t *remote = NewRemote(sockfd);
    int r = connect(sockfd, des_addr->ai_addr, des_addr->ai_addrlen);
    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
        ERROR("connect");
        CloseAndFreeRemote(EV_A_ remote);
        return NULL;
    }

    remote->send_ctx->connected = 1;
    return remote;
}

static remote_t * ConnectToRemote(EV_P_ struct addrinfo *res, server_t *server) {
    int sockfd;
#ifdef SET_INTERFACE
    const char *iface = server->listen_ctx->iface;
#endif

    if (acl) {
        char ipstr[INET6_ADDRSTRLEN];
        memset(ipstr, 0, INET6_ADDRSTRLEN);

        if (res->ai_addr->sa_family == AF_INET) {
            struct sockaddr_in s;
            memcpy(&s, res->ai_addr, sizeof(struct sockaddr_in));
            inet_ntop(AF_INET, &s.sin_addr, ipstr, INET_ADDRSTRLEN);
        } else if (res->ai_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 s;
            memcpy(&s, res->ai_addr, sizeof(struct sockaddr_in6));
            inet_ntop(AF_INET6, &s.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        }

        if (outbound_block_match_host(ipstr) == 1) {
            return NULL;
        }
    }

    // initialize remote socks
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // setup remote socks

    if (SetNonblocking(sockfd) == -1)
        ERROR("SetNonblocking");

#ifdef SET_INTERFACE
    if (iface) {
        if (setinterface(sockfd, iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            return NULL;
    }
}
#endif

    remote_t *remote = NewRemote(sockfd);

    if (fast_open) {
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
        int s = -1;
        s = sendto(sockfd, server->buf->data, server->buf->len,
            MSG_FASTOPEN, res->ai_addr, res->ai_addrlen);
#elif defined(TCP_FASTOPEN_WINSOCK)
        DWORD s = -1;
        DWORD err = 0;
        do {
            int optval = 1;
            // Set fast open option
            if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN,
                &optval, sizeof(optval)) != 0) {
                ERROR("setsockopt");
                break;
            }
            // Load ConnectEx function
            LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
            if (ConnectEx == NULL) {
                LOGE("Cannot load ConnectEx() function");
                err = WSAENOPROTOOPT;
                break;
            }
            // ConnectEx requires a bound socket
            if (winsock_dummybind(sockfd, res->ai_addr) != 0) {
                ERROR("bind");
                break;
            }
            // Call ConnectEx to send data
            memset(&remote->olap, 0, sizeof(remote->olap));
            remote->connect_ex_done = 0;
            if (ConnectEx(sockfd, res->ai_addr, res->ai_addrlen,
                server->buf->data, server->buf->len,
                &s, &remote->olap)) {
                remote->connect_ex_done = 1;
                break;
            }
            // XXX: ConnectEx pending, check later in remote_send
            if (WSAGetLastError() == ERROR_IO_PENDING) {
                err = CONNECT_IN_PROGRESS;
                break;
            }
            ERROR("ConnectEx");
        } while (0);
        // Set error number
        if (err) {
            SetLastError(err);
}
#else
        int s = -1;
#if defined(TCP_FASTOPEN_CONNECT)
        int optval = 1;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
            (void *)&optval, sizeof(optval)) < 0)
            FATAL("failed to set TCP_FASTOPEN_CONNECT");
        s = connect(sockfd, res->ai_addr, res->ai_addrlen);
#elif defined(CONNECT_DATA_IDEMPOTENT)
        struct sockaddr_in sa;
        memcpy(&sa, res->ai_addr, sizeof(struct sockaddr_in));
        sa.sin_len = sizeof(struct sockaddr_in);
        sa_endpoints_t endpoints;
        memset((char *)&endpoints, 0, sizeof(endpoints));
        endpoints.sae_dstaddr = (struct sockaddr *)&sa;
        endpoints.sae_dstaddrlen = res->ai_addrlen;

        s = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_DATA_IDEMPOTENT,
            NULL, 0, NULL, NULL);
#else
        FATAL("fast open is not enabled in this build");
#endif
        if (s == 0)
            s = send(sockfd, server->buf->data, server->buf->len, 0);
#endif
        if (s == -1) {
            if (errno == CONNECT_IN_PROGRESS) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            }
            else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("fast_open_connect");
            }
        } else {
            server->buf->idx += s;
            server->buf->len -= s;
        }
    }

    if (!fast_open) {
        int r = connect(sockfd, res->ai_addr, res->ai_addrlen);
        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            CloseAndFreeRemote(EV_A_ remote);
            return NULL;
        }
    }

    if (server->sid.key != 0) {
        global_remote_map[server->sid.key] = remote;
    }

    return remote;
}

#ifdef USE_NFCONNTRACK_TOS
int SetMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    server_t *server = (server_t *)data;
    struct dscptracker *tracker = server->tracker;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (setsockopt(server->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

void ConntrackQuery(server_t *server) {
    struct dscptracker *tracker = server->tracker;
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, SetMarkDscpCallback, (void *)server);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(errno));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

void SetTosFromConnmark(remote_t *remote, server_t *server) {
    if (server->tracker && server->tracker->ct) {
        if (server->tracker->mark == 0 && server->tracker->packet_count < MARK_MAX_PACKET) {
            server->tracker->packet_count++;
            ConntrackQuery(server);
        }
    } else {
        socklen_t len;
        struct sockaddr_storage sin;
        len = sizeof(sin);
        if (getsockname(remote->fd, (struct sockaddr *)&sin, &len) == 0) {
            struct sockaddr_storage from_addr;
            len = sizeof from_addr;
            if (getpeername(remote->fd, (struct sockaddr *)&from_addr, &len) == 0) {
                if ((server->tracker = (struct dscptracker *)ss_malloc(sizeof(struct dscptracker)))) {
                    if ((server->tracker->ct = nfct_new())) {
                        // Build conntrack query SELECT
                        if (from_addr.ss_family == AF_INET) {
                            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
                            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin_port);
                        } else if (from_addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
                            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET6);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin6_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin6_port);
                        }
                        nfct_set_attr_u8(server->tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
                        ConntrackQuery(server);
                    } else {
                        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
                        server->tracker->ct = NULL;
                    }
                }
            }
        }
    }
}

#endif

static bool RemoveNotAliveAccount(
        const std::chrono::steady_clock::time_point& now_point,
        std::unordered_map<std::string, service::BandwidthInfoPtr>& account_bindwidth_map) {
    if (account_bindwidth_map.size() >= 1024) {
        account_bindwidth_map.clear();
    }
//     for (auto iter = account_bindwidth_map.begin(); iter != account_bindwidth_map.end();) {
//         if ((iter->second->timeout + std::chrono::microseconds(kVpnClientTimeout)) < now_point) {
//             account_bindwidth_map.erase(iter++);
//         } else {
//             ++iter;
//         }
//     }
// 
//     if (account_bindwidth_map.size() > kMaxConnectAccount) {
//         return true;
//     }
    
    return false;
}

static void ServerRecvCallback(EV_P_ ev_io *w, int revents) {
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server = server_recv_ctx->server;
    remote_t *remote = NULL;

    buffer_t *buf = server->buf;

    if (server->stage == STAGE_STREAM) {
        remote = server->remote;
        buf = remote->buf;
        ev_timer_again(EV_A_ & server->recv_ctx->watcher);
    }


    ssize_t r = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);
    if (r == 0) {
        // connection closed
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    }
    else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    // Ignore any new packet if the server is stopped
    if (server->stage == STAGE_STOP) {
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    buf->len = r;
    global_server_passed_bandwidth += r;
    if (global_server_passed_bandwidth > 10 * 1024 * 1024) {
        service::BandwidthManager::Instance()->AddServerBandwidth(global_server_passed_bandwidth);
        global_server_passed_bandwidth = 0;
    }

    std::string pubkey;
    PeerInfo* client_ptr = nullptr;
    if (server->stage == STAGE_INIT) {
        int header_offset = tenon::security::kPublicKeySize * 2;
        bool valid = false;
        uint8_t method_len = *(uint8_t *)(buf->data + header_offset);
        std::string client_platform;
        if (method_len + header_offset + 1 >= static_cast<int>(buf->len)) {
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        client_platform = std::string((char*)buf->data + header_offset + 1, method_len);
        if (client_platform == "and" || client_platform == "aes-128-cfb") {
            send(
                    server->fd,
                    common::kServerClientOverload.c_str(),
                    common::kServerClientOverload.size(), 0);
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        pubkey = std::string((char*)buf->data, header_offset);
        VPNSVR_ERROR("client platform and version: %s, pubkey: %s", client_platform.c_str(), pubkey.c_str());
        client_ptr = tenon::service::AccountWithSecret::Instance()->NewPeer(
                common::Encode::HexDecode(pubkey),
                common::kDefaultEnocdeMethod);
        if (client_ptr == nullptr) {
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        auto now_point = std::chrono::steady_clock::now();
        auto& user_account = client_ptr->account;
        auto& account_map = tenon::vpn::VpnServer::Instance()->account_bindwidth_map();
        auto iter = account_map.find(user_account);
        if (iter == account_map.end()) {
            auto acc_item = std::make_shared<service::BandwidthInfo>(r, 0, user_account, client_platform);
            account_map[user_account] = acc_item;
            if (RemoveNotAliveAccount(now_point, account_map)) {
                // exceeded max user account, new join failed
                // send back with status
                send(
                        server->fd,
                        common::kServerClientOverload.c_str(),
                        common::kServerClientOverload.size(), 0);
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
            tenon::vpn::VpnServer::Instance()->bandwidth_queue().push(acc_item);
            service::BandwidthManager::Instance()->AddClientBandwidthInfo(acc_item);
        } else {
            if (!iter->second->Valid()) {
                send(
                        server->fd,
                        common::kClientFreeBandwidthOver.c_str(),
                        common::kClientFreeBandwidthOver.size(), 0);
                // send back with status
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }

            iter->second->up_bandwidth += r;
            // transaction now with bandwidth
            if (iter->second->timeout + std::chrono::microseconds(kVpnClientTimeout) < now_point) {
                tenon::vpn::VpnServer::Instance()->bandwidth_queue().push(iter->second);
                service::BandwidthManager::Instance()->AddClientBandwidthInfo(iter->second);
            }
            iter->second->timeout = now_point;
        }

        server->client_ptr = client_ptr;
        client_ptr->crypto->ctx_init(client_ptr->crypto->cipher, server->e_ctx, 1);
        client_ptr->crypto->ctx_init(client_ptr->crypto->cipher, server->d_ctx, 0);
        header_offset += method_len + 1;
        memmove(buf->data, buf->data + header_offset, r - header_offset);
        buf->len = r - header_offset;
    } else {
        client_ptr = server->client_ptr;
        if (client_ptr == nullptr) {
            // send back with status
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        auto& account_map = tenon::vpn::VpnServer::Instance()->account_bindwidth_map();
        auto iter = account_map.find(client_ptr->account);
        if (iter == account_map.end()) {
            // send back with status
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        if (!iter->second->Valid()) {
            // send back with status
            send(server->fd,
                    common::kClientFreeBandwidthOver.c_str(),
                    common::kClientFreeBandwidthOver.size(),
                    0);
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    crypto_t* tmp_crypto = client_ptr->crypto;
    int err = tmp_crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);
//     int err = crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);

    if (err == -2) {
        ReportAddr(server->fd, "authentication error");
        StopServer(EV_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        if (server->stage != STAGE_STREAM && server->frag > MAX_FRAG) {
            ReportAddr(server->fd, "malicious fragmentation");
            StopServer(EV_A_ server);
            return;
        }
        server->frag++;
        return;
    }

    // handshake and transmit data
    if (server->stage == STAGE_STREAM) {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
            else {
                ERROR("server_recv_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
        }
        else if (s < static_cast<int>(remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
        return;
    } else if (server->stage == STAGE_INIT) {
        /*
         * Shadowsocks TCP Relay Header:
         *
         *    +------+----------+----------+
         *    | ATYP | DST.ADDR | DST.PORT |
         *    +------+----------+----------+
         *    |  1   | Variable |    2     |
         *    +------+----------+----------+
         *
         */

        int offset = 0;
        int need_query = 0;
        char atyp = server->buf->data[offset++];
        char host[255] = { 0 };
        uint16_t port = 0;
        struct addrinfo info;
        struct sockaddr_storage storage;
        memset(&info, 0, sizeof(struct addrinfo));
        memset(&storage, 0, sizeof(struct sockaddr_storage));

        // get remote addr and port
        if ((atyp & ADDRTYPE_MASK) == 1) {
            // IP V4
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            size_t in_addr_len = sizeof(struct in_addr);
            addr->sin_family = AF_INET;
            if (server->buf->len >= in_addr_len + 3) {
                memcpy(&addr->sin_addr, server->buf->data + offset, in_addr_len);
                inet_ntop(AF_INET, (const void *)(server->buf->data + offset),
                    host, INET_ADDRSTRLEN);
                offset += in_addr_len;
            }
            else {
                ReportAddr(server->fd, "invalid length for ipv4 address");
                StopServer(EV_A_ server);
                return;
            }
            memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family = AF_INET;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen = sizeof(struct sockaddr_in);
            info.ai_addr = (struct sockaddr *)addr;
        }
        else if ((atyp & ADDRTYPE_MASK) == 3) {
            // Domain name
            uint8_t name_len = *(uint8_t *)(server->buf->data + offset);
            if (name_len + 4 <= static_cast<int>(server->buf->len)) {
                memcpy(host, server->buf->data + offset + 1, name_len);
                offset += name_len + 1;
            }
            else {
                ReportAddr(server->fd, "invalid host name length");
                StopServer(EV_A_ server);
                return;
            }
            if (acl && outbound_block_match_host(host) == 1) {
                CloseAndFreeServer(EV_A_ server);
                return;
            }
            struct cork_ip ip;
            if (cork_ip_init(&ip, host) != -1) {
                info.ai_socktype = SOCK_STREAM;
                info.ai_protocol = IPPROTO_TCP;
                if (ip.version == 4) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
                    inet_pton(AF_INET, host, &(addr->sin_addr));
                    memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin_family = AF_INET;
                    info.ai_family = AF_INET;
                    info.ai_addrlen = sizeof(struct sockaddr_in);
                    info.ai_addr = (struct sockaddr *)addr;
                }
                else if (ip.version == 6) {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
                    inet_pton(AF_INET6, host, &(addr->sin6_addr));
                    memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin6_family = AF_INET6;
                    info.ai_family = AF_INET6;
                    info.ai_addrlen = sizeof(struct sockaddr_in6);
                    info.ai_addr = (struct sockaddr *)addr;
                }
            }
            else {
                if (!validate_hostname(host, name_len)) {
                    ReportAddr(server->fd, "invalid host name");
                    StopServer(EV_A_ server);
                    return;
                }
                need_query = 1;
            }
        }
        else if ((atyp & ADDRTYPE_MASK) == 4) {
            // IP V6
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            size_t in6_addr_len = sizeof(struct in6_addr);
            addr->sin6_family = AF_INET6;
            if (server->buf->len >= in6_addr_len + 3) {
                memcpy(&addr->sin6_addr, server->buf->data + offset, in6_addr_len);
                inet_ntop(AF_INET6, (const void *)(server->buf->data + offset),
                    host, INET6_ADDRSTRLEN);
                offset += in6_addr_len;
            }
            else {
                LOGE("invalid header with addr type %d", atyp);
                ReportAddr(server->fd, "invalid length for ipv6 address");
                StopServer(EV_A_ server);
                return;
            }
            memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family = AF_INET6;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen = sizeof(struct sockaddr_in6);
            info.ai_addr = (struct sockaddr *)addr;
        }

        if (offset == 1) {
            ReportAddr(server->fd, "invalid address type");
            StopServer(EV_A_ server);
            return;
        }

        port = ntohs(load16_be(server->buf->data + offset));
        offset += 2;

        if (static_cast<int>(server->buf->len) < offset) {
            ReportAddr(server->fd, "invalid request length");
            StopServer(EV_A_ server);
            return;
        }
        else {
            server->buf->len -= offset;
            memmove(server->buf->data, server->buf->data + offset, server->buf->len);
        }

        if (!need_query) {
            remote_t *remote = ConnectToRemote(EV_A_ & info, server);
            if (remote == NULL) {
                LOGE("connect error");
                CloseAndFreeServer(EV_A_ server);
                return;
            } else {
                server->remote = remote;
                remote->server = server;

                // XXX: should handle buffer carefully
                if (server->buf->len > 0) {
                    brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE * 2 + 1024);
                    memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                        server->buf->len);
                    remote->buf->len = server->buf->len;
                    remote->buf->idx = 0;
                    server->buf->len = 0;
                    server->buf->idx = 0;
                }

                // waiting on remote connected event
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
        } else {
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            query_t *query = (query_t*)ss_malloc(sizeof(query_t));
            memset(query, 0, sizeof(query_t));
            query->server = server;
            server->query = query;
            snprintf(query->hostname, MAX_HOSTNAME_LEN, "%s", host);
            server->stage = STAGE_RESOLVE;
            resolv_start(host, port, ResolvCallback, ResolvFreeCallback, query);
        }
    }
}


static void ServerSendCallback(EV_P_ ev_io *w, int revents) {
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server = server_send_ctx->server;
    remote_t *remote = server->remote;

    if (remote == NULL) {
        LOGE("invalid server");
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
            server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        } else if (s < static_cast<int>(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
        }
    }
}

static void ServerTimeoutCallback(EV_P_ ev_timer *watcher, int revents) {
//     std::lock_guard<std::mutex> guard(global_server_mutex);
    server_ctx_t *server_ctx
        = (server_ctx_t*)cork_container_of(watcher, server_ctx_t, watcher);
    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    CloseAndFreeRemote(EV_A_ remote);
    CloseAndFreeServer(EV_A_ server);
}

static void ResolvFreeCallback(void *data) {
//     std::lock_guard<std::mutex> guard(global_server_mutex);
    query_t *query = (query_t *)data;

    if (query != NULL) {
        if (query->server != NULL)
            query->server->query = NULL;
        ss_free(query);
    }
}

static void ResolvCallback(struct sockaddr *addr, void *data) {
//     std::lock_guard<std::mutex> guard(global_server_mutex);
    query_t *query = (query_t *)data;
    server_t *server = query->server;
    if (server == NULL)
        return;

    struct ev_loop *loop = vpn::EvLoopManager::Instance()->loop(); // server->listen_ctx->loop;
    if (addr == NULL) {
        LOGE("unable to resolve %s", query->hostname);
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    struct addrinfo info;
    memset(&info, 0, sizeof(struct addrinfo));
    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = IPPROTO_TCP;
    info.ai_addr = addr;

    if (addr->sa_family == AF_INET) {
        info.ai_family = AF_INET;
        info.ai_addrlen = sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        info.ai_family = AF_INET6;
        info.ai_addrlen = sizeof(struct sockaddr_in6);
    }

    remote_t *remote = ConnectToRemote(EV_A_ & info, server);
    if (remote == NULL) {
        CloseAndFreeServer(EV_A_ server);
    } else {
        server->remote = remote;
        remote->server = server;
        if (server->buf->len > 0) {
            brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE * 2 + 1024);
            memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                server->buf->len);
            remote->buf->len = server->buf->len;
            remote->buf->idx = 0;
            server->buf->len = 0;
            server->buf->idx = 0;
        }

        ev_io_start(EV_A_ & remote->send_ctx->io);
    }
}

static void RemoteRecvCallback(EV_P_ ev_io *w, int revents) {
//     std::lock_guard<std::mutex> guard(global_server_mutex);
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote = remote_recv_ctx->remote;
    server_t *server = remote->server;
    if (remote->vlan_conn != NULL) {
        ssize_t r = recv(remote->fd, remote->buf->data, SOCKET_BUF_SIZE, 0);
        if (r == 0) {
            // connection closed
            vpn::TcpRelayClientManager::Instance()->RemoveVlanRemote((vpn::VlanConnection*)remote->vlan_conn);
            CloseAndFreeRemote(EV_A_ remote);
            return;
        } else if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                ERROR("remote recv");
                vpn::TcpRelayClientManager::Instance()->RemoveVlanRemote((vpn::VlanConnection*)remote->vlan_conn);
                CloseAndFreeRemote(EV_A_ remote);
                return;
            }
        }

        vpn::TcpRelayClientManager::Instance()->HandleMessage((vpn::VlanConnection*)remote->vlan_conn, remote->buf->data, r);
        return;
    }

    if (server == NULL) {
        LOGE("invalid server");
        CloseAndFreeRemote(EV_A_ remote);
        return;
    }

    if (remote->freed) {
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);
    if (r == 0) {
        // connection closed
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    // Ignore any new packet if the server is stopped
    if (server->stage == STAGE_STOP) {
        return;
    }

    server->buf->len = r;
    global_server_passed_bandwidth += r;
    if (global_server_passed_bandwidth > 10 * 1024 * 1024) {
        service::BandwidthManager::Instance()->AddServerBandwidth(global_server_passed_bandwidth);
        global_server_passed_bandwidth = 0;
    }

    if (server->client_ptr == nullptr) {
        return;
    }

    auto now_point = std::chrono::steady_clock::now();
    auto& user_account = server->client_ptr->account;
    auto& account_map = tenon::vpn::VpnServer::Instance()->account_bindwidth_map();
    auto iter = account_map.find(user_account);
    if (iter == account_map.end()) {
        return;
    } else {
        iter->second->down_bandwidth += r;
        iter->second->timeout = now_point;
    }
    crypto_t* tmp_crypto = server->client_ptr->crypto;
    if (tmp_crypto == NULL) {
        return;
    }

//     int err = crypto->encrypt(server->buf, server->e_ctx, SOCKET_BUF_SIZE);
    int err = tmp_crypto->encrypt(server->buf, server->e_ctx, SOCKET_BUF_SIZE);
    if (err) {
        LOGE("invalid password or cipher");
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    }

#ifdef USE_NFCONNTRACK_TOS
    SetTosFromConnmark(remote, server);
#endif
    remote->recv_ctx->connected = 1;
    if (remote->server->sid.ids.stream_id != 0) {
        if (!remote->recv_ctx->connected && !no_delay) {
            int opt = 0;
            setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        }

        vpn::VpnServer::Instance()->SendStreamData(server, remote);
    } else {
        int s = send(server->fd, server->buf->data, server->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                server->buf->idx = 0;
                ev_io_stop(EV_A_ & remote_recv_ctx->io);
                ev_io_start(EV_A_ & server->send_ctx->io);
            } else {
                ERROR("remote_recv_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
        } else if (s < static_cast<int>(server->buf->len)) {
            server->buf->len -= s;
            server->buf->idx = s;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        }

        // Disable TCP_NODELAY after the first response are sent
        if (!remote->recv_ctx->connected && !no_delay) {
            int opt = 0;
            setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
            setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        }
    }
}

static void RemoteSendCallback(EV_P_ ev_io *w, int revents) {
//     std::lock_guard<std::mutex> guard(global_server_mutex);
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote = remote_send_ctx->remote;
    server_t *server = remote->server;
    if (remote->vlan_conn == NULL && server == NULL) {
        LOGE("invalid server");
        CloseAndFreeRemote(EV_A_ remote);
        return;
    }

    if (remote->freed) {
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                    &numBytes, FALSE, &flags)) {
                    remote->buf->len -= numBytes;
                    remote->buf->idx = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    CloseAndFreeRemote(EV_A_ remote);
                    CloseAndFreeServer(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);

        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            // connection connected, stop the request timeout timer
            ev_timer_stop(EV_A_ & server->recv_ctx->watcher);

            remote_send_ctx->connected = 1;

            if (remote->buf->len == 0) {
                server->stage = STAGE_STREAM;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
        } else {
            ERROR("getpeername");
            // not connected
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0 && remote->reserve_buf == NULL) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        if (remote->reserve_buf != NULL) {
            if (remote->reserve_buf->len == 0 || remote->reserve_buf->len <= remote->reserve_buf->idx) {
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
            ssize_t s = send(remote->fd, remote->reserve_buf->data + remote->reserve_buf->idx, remote->reserve_buf->len - remote->reserve_buf->idx, 0);
            if (s == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    ERROR("remote_send_send");
                    // close and free
                    CloseAndFreeRemote(EV_A_ remote);
                    CloseAndFreeServer(EV_A_ server);
                }
                return;
            } else if (s < static_cast<int>(remote->reserve_buf->len - remote->reserve_buf->idx)) {
                // partly sent, move memory, wait for the next time to send
                remote->reserve_buf->idx += s;
                return;
            } else {
                // all sent out, wait for reading
                remote->reserve_buf->len = 0;
                remote->reserve_buf->idx = 0;
                remote->hold_to_send = false;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                if (remote->real_remotes != NULL) {
                    for (auto iter = remote->real_remotes->begin(); iter != remote->real_remotes->end(); ++iter) {
                        (*iter)->hold_by_vlan_remote = false;
                        if ((*iter)->freed) {
                            continue;
                        }

                        ev_io_start(EV_A_ & (*iter)->recv_ctx->io);
                    }
                    remote->real_remotes->clear();
                }

                if (remote->hold_valn_to_internet) {
                    remote->hold_valn_to_internet = false;
                    vpn::TcpRelayClientManager::Instance()->ResetRemoteStatus(remote->server->sid.key, 0);
                }
            }
            return;
        }

        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx, remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        } else if (s < static_cast<int>(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        }
    }
}

static remote_t * NewRemote(int fd) {
    remote_t *remote = (remote_t*)ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = (remote_ctx_t*)ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = (remote_ctx_t*)ss_malloc(sizeof(remote_ctx_t));
    remote->buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE * 2 + 1024);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd = fd;
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->server = NULL;

    ev_io_init(&remote->recv_ctx->io, RemoteRecvCallback, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, RemoteSendCallback, fd, EV_WRITE);

    return remote;
}

static void FreeRemote(remote_t *remote) {
    remote->freed = true;
    if (remote->hold_by_vlan_remote || remote->hold_by_valn_queue) {
        return;
    }
    
    if (remote->reserve_buf != NULL) {
        bfree(remote->reserve_buf);
        free(remote->reserve_buf);
    }

    if (remote->server != NULL) {
        remote->server->remote = NULL;
        auto iter = global_remote_map.find(remote->server->sid.key);
        if (iter != global_remote_map.end()) {
            // send free route server
            global_remote_map.erase(iter);
        }
    }

    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }


    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void CloseAndFreeRemote(EV_P_ remote_t *remote) {
    if (remote != NULL) {
        if (remote->send_ctx != NULL) {
            ev_io_stop(EV_A_ & remote->send_ctx->io);
        }
        if (remote->recv_ctx != NULL) {
            ev_io_stop(EV_A_ & remote->recv_ctx->io);
        }
        if (remote->fd > 0)
            close(remote->fd);
        FreeRemote(remote);
    }
}

static server_t * NewServer(int fd, listen_ctx_t *listener) {
    server_t *server;
    server = (server_t*)ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));
    server->recv_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, SOCKET_BUF_SIZE * 2 + 1024);
    server->fd = fd;
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    server->stage = STAGE_INIT;
    server->frag = 0;
    server->query = NULL;
    server->listen_ctx = listener;
    server->remote = NULL;
    server->svr_item = listener->svr_item;
    server->e_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
//     crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
//     crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    int request_timeout = std::min(MAX_REQUEST_TIMEOUT, listener->timeout)
        + rand() % MAX_REQUEST_TIMEOUT;

    ev_io_init(&server->recv_ctx->io, ServerRecvCallback, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, ServerSendCallback, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, ServerTimeoutCallback,
        MAX_REQUEST_TIMEOUT, 0);

    cork_dllist_add(&server->svr_item->connections, &server->entries);

    return server;
}

static void FreeServer(server_t *server) {
#ifdef USE_NFCONNTRACK_TOS
    if (server->tracker) {
        struct dscptracker *tracker = server->tracker;
        struct nf_conntrack *ct = server->tracker->ct;
        server->tracker = NULL;
        if (ct) {
            nfct_destroy(ct);
        }
        free(tracker);
    }
#endif
    server->stage = STAGE_STOP;
    if (server->sid.ids.stream_id == 0) {
        cork_dllist_remove(&server->entries);
    }

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }

    crypto_t* tmp_crypto = NULL;
    if (server->client_ptr != nullptr) {
        tmp_crypto = server->client_ptr->crypto;
    }

    if (server->e_ctx != NULL) {
        if (tmp_crypto != NULL) {
            tmp_crypto->ctx_release(server->e_ctx);
        }
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        if (tmp_crypto != NULL) {
            tmp_crypto->ctx_release(server->d_ctx);
        }
        ss_free(server->d_ctx);
    }

    if (tmp_crypto != NULL) {
//         ss_free(tmp_crypto);
    }

    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }

    auto iter = global_server_map.find(server->sid.key);
    if (iter != global_server_map.end()) {
        global_server_map.erase(iter);
    }

    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void CloseAndFreeServer(EV_P_ server_t *server) {
    if (server != NULL) {
        if (server->sid.ids.id != 0 && server->sid.ids.stream_id > 0x80000000u) {
            global_removed_server_set.insert(server->sid.key);
            vpn::TcpRelayClientManager::Instance()->SendStopServer(
                    server->sid.ids.stream_id,
                    server->sid.ids.id);
        }

        if (server->query != NULL) {
            server->query->server = NULL;
            server->query = NULL;
        }

        if (server->send_ctx != NULL) {
            ev_io_stop(EV_A_ & server->send_ctx->io);
        }

        if (server->recv_ctx != NULL) {
            ev_io_stop(EV_A_ & server->recv_ctx->io);
            ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        }

        if (server->fd > 0)
            close(server->fd);
        FreeServer(server);
    }
}

static void AcceptCallback(EV_P_ ev_io *w, int revents) {
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    char *peer_name = GetPeerName(serverfd);
    if (peer_name != NULL) {
        if (acl) {
            if ((get_acl_mode() == BLACK_LIST && acl_match_host(peer_name) == 1)
                || (get_acl_mode() == WHITE_LIST && acl_match_host(peer_name) >= 0)) {
                LOGE("Access denied from %s", peer_name);
                close(serverfd);
                return;
            }
        }
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    SetNonblocking(serverfd);

    server_t *server = NewServer(serverfd, listener);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

static int StartTcpServer(
        const std::string& host,
        uint16_t port,
        listen_ctx_t* listen_ctx) {
    const char* remote_port = (char*)std::to_string(port).c_str();

    int listenfd;
    listenfd = CreateAndBind(host.c_str(), remote_port, 0);
    if (listenfd == -1) {
        return -1;
    }

    if (listen(listenfd, SSMAXCONN) == -1) {
        LOGI("listen()");
        return -1;
    }
    SetFastopen(listenfd);
    SetNonblocking(listenfd);

    listen_ctx->timeout = 60;
    listen_ctx->fd = listenfd;
    listen_ctx->iface = NULL;
    listen_ctx->loop = vpn::EvLoopManager::Instance()->loop();
    listen_ctx->svr_item = (server_item_t*)ss_malloc(sizeof(server_item_t));
    ev_io_init(&listen_ctx->io, AcceptCallback, listenfd, EV_READ);
    ev_io_start(vpn::EvLoopManager::Instance()->loop(), &listen_ctx->io);
    return 0;
}

// static int StartUdpServer(const std::string& host, uint16_t port) {
//     int err = init_udprelay(host.c_str(), std::to_string(port).c_str(), 1500, crypto, 60, NULL);
//     if (err == -1) {
//         return -1;
//     }
//     return 0;
// }

static void StopVpn(listen_ctx_t* listen_ctx) {
    ev_io_stop(vpn::EvLoopManager::Instance()->loop(), &listen_ctx->io);
    close(listen_ctx->fd);
    FreeConnections(
            vpn::EvLoopManager::Instance()->loop(),
            &listen_ctx->svr_item->connections);
#ifdef __MINGW32__
        if (plugin_watcher.valid) {
            closesocket(plugin_watcher.fd);
        }

        winsock_cleanup();
#endif
}

static server_t * UdpNewServer() {
    server_t *server;
    server = (server_t*)ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));
    server->recv_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, SOCKET_BUF_SIZE * 2 + 1024);
    server->fd = 0;
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    server->stage = STAGE_INIT;
    server->frag = 0;
    server->query = NULL;
    server->listen_ctx = NULL;
    server->remote = NULL;
    server->svr_item = NULL;
    server->e_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    return server;
}

static int ClientRecvCallback(
        uint32_t server_id,
        uint32_t stream_id,
        char* data,
        uint32_t len) {
    ServerKey skey;
    skey.ids.id = server_id;
    skey.ids.stream_id = stream_id;
    auto remove_iter = global_removed_server_set.find(skey.key);
    if (remove_iter != global_removed_server_set.end()) {
        vpn::TcpRelayClientManager::Instance()->SendStopServer(stream_id, server_id);
        return 0;
    }

    if (stream_id == 0 && data == NULL && len == 0) {
        auto riter = global_remote_map.find(skey.key);
        if (riter != global_remote_map.end()) {
            riter->second->freed = true;
            global_remote_map.erase(riter);
        }

        return 0;
    }

    struct ev_loop *loop = vpn::EvLoopManager::Instance()->loop();
    server_t* server = nullptr;
    auto siter = global_server_map.find(skey.key);
    if (siter == global_server_map.end()) {
        server = UdpNewServer();
        server->sid = skey;
        global_server_map[skey.key] = server;
    } else {
        server = siter->second;
    }

    ssize_t r = len;
    remote_t *remote = NULL;
    buffer_t* buf = NULL;
    auto riter = global_remote_map.find(server->sid.key);
    if (riter != global_remote_map.end()) {
        remote = riter->second;
        if (remote->buf->len > 0) {
            if (server->stage == STAGE_INIT) {
                LOGE("11111111111 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
                return 0;
            }
        }
    }

    if (remote != NULL) {
        memcpy(remote->buf->data , data, len);
        remote->buf->len = len;
        buf = remote->buf;
    } else {
        memcpy(server->buf->data, data, len);
        server->buf->len = len;
        buf = server->buf;
    }

    if (r == 0) {
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return 1;
    }

    std::string pubkey;
    PeerInfo* client_ptr = nullptr;
    if (server->stage == STAGE_INIT) {
        int header_offset = tenon::security::kPublicKeySize * 2;
        bool valid = false;
        uint8_t method_len = *(uint8_t *)(buf->data + header_offset);
        std::string client_platform;
        if (method_len + header_offset + 1 >= static_cast<int>(buf->len)) {
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return 1;
        }

        client_platform = std::string((char*)buf->data + header_offset + 1, method_len);
        pubkey = std::string((char*)buf->data, header_offset);
        client_ptr = tenon::service::AccountWithSecret::Instance()->NewPeer(
                common::Encode::HexDecode(pubkey),
                common::kDefaultEnocdeMethod);
        if (client_ptr == nullptr) {
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return 1;
        }

        auto now_point = std::chrono::steady_clock::now();
        auto& user_account = client_ptr->account;
        auto& account_map = tenon::vpn::VpnServer::Instance()->account_bindwidth_map();
        auto iter = account_map.find(user_account);
        if (iter == account_map.end()) {
            auto acc_item = std::make_shared<service::BandwidthInfo>(r, 0, user_account, client_platform);
            account_map[user_account] = acc_item;
            if (RemoveNotAliveAccount(now_point, account_map)) {
                // exceeded max user account, new join failed
                // send back with status
//                 send(
//                         server->fd,
//                         common::kServerClientOverload.c_str(),
//                         common::kServerClientOverload.size(), 0);
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return 1;
            }
            tenon::vpn::VpnServer::Instance()->bandwidth_queue().push(acc_item);
        } else {
            if (!iter->second->Valid()) {
//                 send(
//                         server->fd,
//                         common::kClientFreeBandwidthOver.c_str(),
//                         common::kClientFreeBandwidthOver.size(), 0);
                // send back with status
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return 1;
            }

            iter->second->up_bandwidth += r;
            // transaction now with bandwidth
            if (iter->second->timeout + std::chrono::microseconds(kVpnClientTimeout) < now_point) {
                tenon::vpn::VpnServer::Instance()->bandwidth_queue().push(iter->second);
            }
            iter->second->timeout = now_point;
        }

        server->client_ptr = client_ptr;
        client_ptr->crypto->ctx_init(client_ptr->crypto->cipher, server->e_ctx, 1);
        client_ptr->crypto->ctx_init(client_ptr->crypto->cipher, server->d_ctx, 0);
        header_offset += method_len + 1;
        memmove(buf->data, buf->data + header_offset, r - header_offset);
        buf->len = r - header_offset;
    } else {
        client_ptr = server->client_ptr;
        if (client_ptr == nullptr) {
            // send back with status
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return 1;
        }

        auto& account_map = tenon::vpn::VpnServer::Instance()->account_bindwidth_map();
        auto iter = account_map.find(client_ptr->account);
        if (iter == account_map.end()) {
            // send back with status
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return 1;
        }

        if (!iter->second->Valid()) {
            // send back with status
//             send(server->fd,
//                     common::kClientFreeBandwidthOver.c_str(),
//                     common::kClientFreeBandwidthOver.size(),
//                     0);
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return 1;
        }
    }

    crypto_t* tmp_crypto = client_ptr->crypto;
    int err = tmp_crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);
    if (err == -2) {
        return 0;
    } else if (err == CRYPTO_NEED_MORE) {
        if (server->stage != STAGE_STREAM && server->frag > MAX_FRAG) {
            return 0;
        }
        server->frag++;
        return 0;
    }

    // handshake and transmit data
    if (server->stage == STAGE_STREAM) {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_start(EV_A_ & remote->send_ctx->io);
                remote->hold_valn_to_internet = true;
                return -1;
            } else {
                ERROR("server_recv_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return 1;
            }
        } else if (s < static_cast<int>(remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx = s;
            remote->hold_valn_to_internet = true;
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return -1;
        } else {
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote->send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
        return 0;
    } else if (server->stage == STAGE_INIT) {
        /*
         * Shadowsocks TCP Relay Header:
         *
         *    +------+----------+----------+
         *    | ATYP | DST.ADDR | DST.PORT |
         *    +------+----------+----------+
         *    |  1   | Variable |    2     |
         *    +------+----------+----------+
         *
         */

        int offset = 0;
        int need_query = 0;
        char atyp = server->buf->data[offset++];
        char host[255] = { 0 };
        uint16_t port = 0;
        struct addrinfo info;
        struct sockaddr_storage storage;
        memset(&info, 0, sizeof(struct addrinfo));
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        // get remote addr and port
        if ((atyp & ADDRTYPE_MASK) == 1) {
            // IP V4
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            size_t in_addr_len = sizeof(struct in_addr);
            addr->sin_family = AF_INET;
            if (server->buf->len >= in_addr_len + 3) {
                memcpy(&addr->sin_addr, server->buf->data + offset, in_addr_len);
                inet_ntop(AF_INET, (const void *)(server->buf->data + offset),
                    host, INET_ADDRSTRLEN);
                offset += in_addr_len;
            }
            else {
                ReportAddr(server->fd, "invalid length for ipv4 address");
                StopServer(EV_A_ server);
                return 0;
            }
            memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family = AF_INET;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen = sizeof(struct sockaddr_in);
            info.ai_addr = (struct sockaddr *)addr;
        } else if ((atyp & ADDRTYPE_MASK) == 3) {
            // Domain name
            uint8_t name_len = *(uint8_t *)(server->buf->data + offset);
            memcpy(host, server->buf->data + offset + 1, name_len);
            if (name_len + 4 <= static_cast<int>(server->buf->len)) {
                memcpy(host, server->buf->data + offset + 1, name_len);
                offset += name_len + 1;
            }
            else {
                ReportAddr(server->fd, "invalid host name length");
                StopServer(EV_A_ server);
                return 0;
            }
            if (acl && outbound_block_match_host(host) == 1) {
                CloseAndFreeServer(EV_A_ server);
                return 0;
            }
            struct cork_ip ip;
            if (cork_ip_init(&ip, host) != -1) {
                info.ai_socktype = SOCK_STREAM;
                info.ai_protocol = IPPROTO_TCP;
                if (ip.version == 4) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
                    inet_pton(AF_INET, host, &(addr->sin_addr));
                    memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin_family = AF_INET;
                    info.ai_family = AF_INET;
                    info.ai_addrlen = sizeof(struct sockaddr_in);
                    info.ai_addr = (struct sockaddr *)addr;
                }
                else if (ip.version == 6) {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
                    inet_pton(AF_INET6, host, &(addr->sin6_addr));
                    memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin6_family = AF_INET6;
                    info.ai_family = AF_INET6;
                    info.ai_addrlen = sizeof(struct sockaddr_in6);
                    info.ai_addr = (struct sockaddr *)addr;
                }
            }
            else {
                if (!validate_hostname(host, name_len)) {
                    ReportAddr(server->fd, "invalid host name");
                    return 0;
                }
                need_query = 1;
            }
        }
        else if ((atyp & ADDRTYPE_MASK) == 4) {
            // IP V6
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            size_t in6_addr_len = sizeof(struct in6_addr);
            addr->sin6_family = AF_INET6;
            if (server->buf->len >= in6_addr_len + 3) {
                memcpy(&addr->sin6_addr, server->buf->data + offset, in6_addr_len);
                inet_ntop(AF_INET6, (const void *)(server->buf->data + offset),
                    host, INET6_ADDRSTRLEN);
                offset += in6_addr_len;
            }
            else {
                LOGE("invalid header with addr type %d", atyp);
                ReportAddr(server->fd, "invalid length for ipv6 address");
                return 0;
            }
            memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family = AF_INET6;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen = sizeof(struct sockaddr_in6);
            info.ai_addr = (struct sockaddr *)addr;
        }

        if (offset == 1) {
            ReportAddr(server->fd, "invalid address type");
            return 0;
        }

        port = ntohs(load16_be(server->buf->data + offset));
        offset += 2;
        if (static_cast<int>(server->buf->len) < offset) {
            ReportAddr(server->fd, "invalid request length");
            StopServer(EV_A_ server);
            return 0;
        } else {
            server->buf->len -= offset;
            memmove(server->buf->data, server->buf->data + offset, server->buf->len);
        }

        if (!need_query) {
            remote_t *remote = ConnectToRemote(EV_A_ & info, server);
            if (remote == NULL) {
                LOGE("connect error");
                CloseAndFreeServer(EV_A_ server);
                return 0;
            } else {
                server->remote = remote;
                remote->server = server;
                // XXX: should handle buffer carefully
                if (server->buf->len > 0) {
                    brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE * 2 + 1024);
                    memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                        server->buf->len);
                    remote->buf->len = server->buf->len;
                    remote->buf->idx = 0;
                    server->buf->len = 0;
                    server->buf->idx = 0;
                }

                // waiting on remote connected event
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
            server->stage = 7;
        } else {
            query_t *query = (query_t*)ss_malloc(sizeof(query_t));
            memset(query, 0, sizeof(query_t));
            query->server = server;
            server->query = query;
            snprintf(query->hostname, MAX_HOSTNAME_LEN, "%s", host);
            server->stage = STAGE_RESOLVE;
            resolv_start(host, port, ResolvCallback, ResolvFreeCallback, query);
        }
    }
    return 0;
}

namespace tenon {

namespace vpn {

VpnServer::VpnServer() : ev_udp_transport_(886080u, 886080u) {
    ev_udp_transport_.Init();
    vip_committee_accounts_.insert(common::Encode::HexDecode("dc161d9ab9cd5a031d6c5de29c26247b6fde6eb36ed3963c446c1a993a088262"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("5595b040cdd20984a3ad3805e07bad73d7bf2c31e4dc4b0a34bc781f53c3dff7"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("25530e0f5a561f759a8eb8c2aeba957303a8bb53a54da913ca25e6aa00d4c365"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("9eb2f3bd5a78a1e7275142d2eaef31e90eae47908de356781c98771ef1a90cd2"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("c110df93b305ce23057590229b5dd2f966620acd50ad155d213b4c9db83c1f36"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("f64e0d4feebb5283e79a1dfee640a276420a08ce6a8fbef5572e616e24c2cf18"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("7ff017f63dc70770fcfe7b336c979c7fc6164e9653f32879e55fcead90ddf13f"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("6dce73798afdbaac6b94b79014b15dcc6806cb693cf403098d8819ac362fa237"));
    vip_committee_accounts_.insert(common::Encode::HexDecode("b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4"));
    for (auto iter = vip_committee_accounts_.begin(); iter != vip_committee_accounts_.end(); ++iter) {
        valid_client_account_.insert(*iter);
    }

    valid_client_account_.insert(common::Encode::HexDecode("b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4"));
    valid_client_account_.insert(common::Encode::HexDecode("ba960f8ff67202eb2fb61ef1023731d1e4d0258b5f594d47a3181f58857762d0"));
    valid_client_account_.insert(common::Encode::HexDecode("6b9b6d3dbc8ae849b92ce86a52a5ed6ae8fe11a0ba9b4066d76147c617f0575a"));
    valid_client_account_.insert(common::Encode::HexDecode("a1979a5af9a7b36328631be5f39e9f7c49121a85d584300bb0089e4393c1ca69"));
    valid_client_account_.insert(common::Encode::HexDecode("91c395027c490589db3fa68fae59c85dded67b07f95bc94ef2ce47a0c01f580c"));
    valid_client_account_.insert(common::Encode::HexDecode("f5e4110421da112fea110b6ac4d0ac21ea2069b10edd9e1cd53ce340a1b5f61e"));
    valid_client_account_.insert(common::Encode::HexDecode("3f4621678cb66e4a5510314689547967171fa8c8b9dc104db70a961babbc0e77"));
    valid_client_account_.insert(common::Encode::HexDecode("e887bbd4aa190114754bfc813865b3cbd7d2b57c286442ffd61dbb66b706d683"));
    valid_client_account_.insert(common::Encode::HexDecode("dd2a148c9ab80aaa62b2ef090ab1887c45ab27e2383a21af285731327b511da6"));
    valid_client_account_.insert(common::Encode::HexDecode("93e4ba2e5598d9c799b65d0d06582d645968873264da0afc249d80906a3fa9d4"));
}

VpnServer::~VpnServer() {}

VpnServer* VpnServer::Instance() {
    static VpnServer ins;
    return &ins;
}

void VpnServer::Stop() {
    while (!listen_ctx_queue_.empty()) {
        auto listen_ctx_ptr = listen_ctx_queue_.front();
        listen_ctx_queue_.pop_front();
        StopVpn(listen_ctx_ptr.get());
    }
}

int VpnServer::Init(uint16_t min_port, uint16_t max_port) {
    network::Route::Instance()->RegisterMessage(
        common::kBlockMessage,
        std::bind(&VpnServer::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
        common::kContractMessage,
        std::bind(&VpnServer::HandleMessage, this, std::placeholders::_1));

    vpn_min_port_ = min_port;
    vpn_max_port_ = max_port;
    admin_vpn_account_ = common::Encode::HexDecode(common::kVpnAdminAccount);
    std::string save_vpn_nodes_msg;
    if (db::Db::Instance()->Get(db::kGlobalDbSaveVpnNodesKey, &save_vpn_nodes_msg).ok()) {
        common::Split<1024> first_split(save_vpn_nodes_msg.c_str(), ',', save_vpn_nodes_msg.size());
        for (uint32_t i = 0; i < first_split.Count(); ++i) {
            common::Split<> sec_split(first_split[i], ':', first_split.SubLen(i));
            if (sec_split.Count() != 2) {
                continue;
            }

            if (sec_split.SubLen(1) < 2) {
                continue;
            }

            vpn_node_used_count_map_[sec_split[0]] = std::map<uint64_t, std::chrono::steady_clock::time_point>();
            common::Split<> third_split(sec_split[1], ';', sec_split.SubLen(1));
            for (uint32_t i = 0; i < third_split.Count(); ++i) {
                if (third_split.SubLen(i) <= 1) {
                    continue;
                }

                vpn_node_used_count_map_[sec_split[0]][common::StringUtil::ToUint64(third_split[i])] =
                        std::chrono::steady_clock::now() + std::chrono::seconds(120);
            }
        }
    }

    CheckVersion();
    RotationServer();
    CheckVpnNodeTimeout();
    if (listen_ctx_queue_.empty()) {
        return kVpnsvrError;
    }

    if (common::GlobalInfo::Instance()->is_vlan_node()) {
        TcpRelayClientManager::Instance()->Init(
                ShadowsocksProxy::Instance()->TcpTransport(),
                ClientRecvCallback);
    }

    ChooseRelayRouteNodes();
    RoutingNodesHeartbeat();
    staking_tick_.CutOff(
            kStakingCheckingPeriod,
            std::bind(&VpnServer::CheckTransactions, VpnServer::Instance()));
    bandwidth_tick_.CutOff(
            kStakingCheckingPeriod,
            std::bind(&VpnServer::CheckAccountValid, VpnServer::Instance()));
    return kVpnsvrSuccess;
}

void VpnServer::HandleMessage(transport::protobuf::Header& header) {
    if (header.has_client() && header.client()) {
        if (header.type() == common::kBlockMessage) {
            block::protobuf::BlockMessage block_msg;
            if (!block_msg.ParseFromString(header.data())) {
                return;
            }

            if (block_msg.has_up_vpn_req()) {
                HandleUpdateVpnCountRequest(header, block_msg);
                return;
            }
        }

        network::Route::Instance()->Send(header);
        return;
    }

    if (header.type() == common::kBlockMessage) {
        block::protobuf::BlockMessage block_msg;
        if (!block_msg.ParseFromString(header.data())) {
            return;
        }

        if (block_msg.has_acc_attr_res()) {
            dht::BaseDhtPtr dht_ptr = nullptr;
            uint32_t netid = dht::DhtKeyManager::DhtKeyGetNetId(header.des_dht_key());
            if (netid == network::kUniversalNetworkId || netid == network::kNodeNetworkId) {
                dht_ptr = network::UniversalManager::Instance()->GetUniversal(netid);
            } else {
                if (header.universal()) {
                    dht_ptr = network::UniversalManager::Instance()->GetUniversal(netid);
                } else {
                    dht_ptr = network::DhtManager::Instance()->GetDht(netid);
                }
            }

            if (dht_ptr == nullptr) {
                network::Route::Instance()->Send(header);
                return;
            }

            if (header.des_dht_key() == dht_ptr->local_node()->dht_key()) {
                HandleVpnLoginResponse(header, block_msg);
                return;
            }
            dht_ptr->SendToClosestNode(header);
        } else if (block_msg.has_up_vpn_req()) {
            HandleUpdateVpnCountRequest(header, block_msg);
            return;
        } else if (block_msg.has_vpn_active_req()) {
            HandleUpdateVpnActiveRequest(header, block_msg);
            return;
        } else if (block_msg.has_account_init_res()) {
            transport::SynchroWait::Instance()->Callback(header.id(), header);
            SaveAccountInitBlocks(header);
            return;
        } else {
            network::Route::Instance()->Send(header);
            return;
        }
    }

    if (header.type() == common::kContractMessage) {
        contract::protobuf::ContractMessage contract_msg;
        if (!contract_msg.ParseFromString(header.data())) {
            return;
        }

        if (contract_msg.has_get_attr_res()) {
            dht::BaseDhtPtr dht_ptr = nullptr;
            uint32_t netid = dht::DhtKeyManager::DhtKeyGetNetId(header.des_dht_key());
            if (netid == network::kUniversalNetworkId || netid == network::kNodeNetworkId) {
                dht_ptr = network::UniversalManager::Instance()->GetUniversal(netid);
            } else {
                if (header.universal() == 0) {
                    dht_ptr = network::UniversalManager::Instance()->GetUniversal(netid);
                } else {
                    dht_ptr = network::DhtManager::Instance()->GetDht(netid);
                }
            }

            if (dht_ptr == nullptr) {
                network::Route::Instance()->Send(header);
                return;
            }

            if (header.des_dht_key() == dht_ptr->local_node()->dht_key()) {
                HandleClientBandwidthResponse(header, contract_msg);
                return;
            }
            dht_ptr->SendToClosestNode(header);
        } else {
            network::Route::Instance()->Send(header);
        }
    }
}

void VpnServer::SaveAccountInitBlocks(transport::protobuf::Header& header) {
    block::protobuf::BlockMessage init_blocks;
    if (!init_blocks.ParseFromString(header.data())) {
        return;
    }

    if (!init_blocks.has_account_init_res()) {
        return;
    }

    std::string key = db::kGlobalDbAccountInitBlocks + "_" + init_blocks.account_init_res().id();
    db::Db::Instance()->Put(key, header.data());
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(header, "");
}

void VpnServer::HandleUpdateVpnActiveRequest(
        transport::protobuf::Header& header,
        block::protobuf::BlockMessage& block_msg) {
    db::DbWriteBach db_batch;
    statis::Statistics::Instance()->inc_active_user_count(
            common::TimeUtils::TimestampMs(),
            block_msg.vpn_active_req().id(),
            db_batch);
    db::Db::Instance()->Put(db_batch);
}

void VpnServer::HandleUpdateVpnCountRequest(
        transport::protobuf::Header& header,
        block::protobuf::BlockMessage& block_msg) {
    {
        std::string key = block_msg.up_vpn_req().ip() + "_" + block_msg.up_vpn_req().uid();
        std::lock_guard<std::mutex> guard(vpn_node_used_count_map_mutex_);
        auto iter = vpn_node_used_count_map_.find(key);
        if (iter == vpn_node_used_count_map_.end()) {
            vpn_node_used_count_map_[key] =
                    std::map<uint64_t, std::chrono::steady_clock::time_point>();
        }

        if (!block_msg.up_vpn_req().old_ip().empty()) {
            std::string old_key = block_msg.up_vpn_req().old_ip() + "_" + block_msg.up_vpn_req().uid();
            auto old_iter = vpn_node_used_count_map_.find(old_key);
            if (old_iter != vpn_node_used_count_map_.end()) {
                old_iter->second.erase(block_msg.up_vpn_req().account_hash());
            }
        }

        if (!block_msg.up_vpn_req().ip().empty()) {
            vpn_node_used_count_map_[key][block_msg.up_vpn_req().account_hash()] =
                    std::chrono::steady_clock::now() + std::chrono::seconds(120);
        }
    }

    if (block_msg.up_vpn_req().just_set()) {
        network::Route::Instance()->Send(header);
        return;
    }

    transport::protobuf::Header broadcast_header = header;
    auto broadcast_param = broadcast_header.mutable_broadcast();
    bft::BftProto::SetDefaultBroadcastParam(broadcast_param);
    block_msg.mutable_up_vpn_req()->set_just_set(true);
    network::Route::Instance()->Send(broadcast_header);

    block::protobuf::BlockMessage block_msg_res;
    {
        auto attr_res = block_msg_res.mutable_up_vpn_res();
        std::lock_guard<std::mutex> guard(vpn_node_used_count_map_mutex_);
        for (auto iter = vpn_node_used_count_map_.begin();
                iter != vpn_node_used_count_map_.end(); ++iter) {
            common::Split<> ip_uid_split(iter->first.c_str(), '_', iter->first.size());
            if (ip_uid_split[1] != block_msg.up_vpn_req().uid()) {
                continue;
            }

            if (!init::UpdateVpnInit::Instance()->IsValidConfitVpnNode(ip_uid_split[0])) {
                continue;
            }

            auto item = attr_res->add_vpn_nodes();
            item->set_ip(ip_uid_split[0]);
            item->set_count(iter->second.size());
        }
    }

    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    block::BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

std::string VpnServer::GetVpnCount(const std::string& uid) {
    std::string res;
    std::lock_guard<std::mutex> guard(vpn_node_used_count_map_mutex_);
    for (auto iter = vpn_node_used_count_map_.begin();
        iter != vpn_node_used_count_map_.end(); ++iter) {
        common::Split<> ip_uid_split(iter->first.c_str(), '_', iter->first.size());
        if (ip_uid_split[1] != uid) {
            continue;
        }

        if (!init::UpdateVpnInit::Instance()->IsValidConfitVpnNode(ip_uid_split[0])) {
            continue;
        }

        res += std::string(ip_uid_split[0]) + ":" + std::to_string(iter->second.size()) + ";";
    }

    return res;
}

void VpnServer::CheckVpnNodeTimeout() {
    std::string save_vpn_nodes_msg;
    auto now_tm = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> guard(vpn_node_used_count_map_mutex_);
        for (auto iter = vpn_node_used_count_map_.begin();
                iter != vpn_node_used_count_map_.end(); ++iter) {
            std::string val;
            for (auto item_iter = iter->second.begin(); item_iter != iter->second.end();) {
                if (item_iter->second < now_tm) {
                    iter->second.erase(item_iter++);
                    continue;
                }

                val += std::to_string(item_iter->first) + ";";
                ++item_iter;
            }

            save_vpn_nodes_msg += iter->first + ":" + val + ",";
        }
    }

    db::Db::Instance()->Put(db::kGlobalDbSaveVpnNodesKey, save_vpn_nodes_msg);
    vpn_node_count_tick_.CutOff(
            kCheckNodeTimeout,
            std::bind(&VpnServer::CheckVpnNodeTimeout, this));
}

int VpnServer::ParserReceivePacket(const char* buf) {
    return 0;
}

void VpnServer::SendGetAccountAttrLastBlock(
        const std::string& attr,
        const std::string& account,
        uint64_t height) {
    auto uni_dht = tenon::network::DhtManager::Instance()->GetDht(
            tenon::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        VPNSVR_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    block::BlockProto::AccountAttrRequest(
            uni_dht->local_node(),
            account,
            attr,
            height,
            msg);
    network::Route::Instance()->Send(msg);
    VPNSVR_ERROR("get block version attr message id: %u", msg.id());
}

void VpnServer::SendGetAccountAttrUsedBandwidth(const std::string& account) {
    auto uni_dht = tenon::network::DhtManager::Instance()->GetDht(
        tenon::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        VPNSVR_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string key = (common::kIncreaseVpnBandwidth + "_" +
            common::Encode::HexEncode(account) + "_" + now_day_timestamp);
    contract::ContractProto::CreateGetAttrRequest(
            uni_dht->local_node(),
            account,
            key,
            msg);
    network::Route::Instance()->Send(msg);
}

void SendClientUseBandwidth(const std::string& id, uint32_t bandwidth) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string attr_key = (common::kIncreaseVpnBandwidth + "_" +
        common::Encode::HexEncode(id) + "_" + now_day_timestamp);
    std::map<std::string, std::string> attrs{
        {attr_key, std::to_string(bandwidth)}
    };
    std::string gid;
    tenon::client::TransactionClient::Instance()->Transaction(
            id,
            0,
            contract::kContractVpnBandwidthProveAddr,
            attrs,
            common::kConsensusVpnBandwidth,
            gid);
}

void VpnServer::CheckTransactions() {
    StakingItemPtr staking_item = nullptr;
    std::map<std::string, std::string> attrs;
    while (staking_queue_.pop(&staking_item)) {
        if (staking_item != nullptr) {
            std::string gid;
            tenon::client::TransactionClient::Instance()->Transaction(
                    staking_item->to,
                    staking_item->amount,
                    "",
                    attrs,
                    common::kConsensusMining,
                    gid);
            // check and retry transaction success
            // gid_map_.insert(std::make_pair(gid, staking_item));
        }
    }
    staking_tick_.CutOff(
            kStakingCheckingPeriod,
            std::bind(&VpnServer::CheckTransactions, VpnServer::Instance()));
}

void VpnServer::HandleClientBandwidthResponse(
        transport::protobuf::Header& header,
        contract::protobuf::ContractMessage& contract_msg) {
    auto client_bw_res = contract_msg.get_attr_res();
    std::string key = client_bw_res.attr_key();
    common::Split<> key_split(key.c_str(), '_', key.size());
    if (key_split.Count() != 3) {
        return;
    }

    uint64_t used = 0;
    try {
        used = common::StringUtil::ToUint64(client_bw_res.attr_value());
    } catch(...) {
        return;
    }

    std::string account_id = common::Encode::HexDecode(key_split[1]);
//     std::lock_guard<std::mutex> guard(account_map_mutex_);
    auto iter = account_map_.find(account_id);
    if (iter == account_map_.end()) {
        return;
    }

    iter->second->today_used_bandwidth = used;
    iter->second->pre_bandwidth_get_time = (std::chrono::steady_clock::now() +
            std::chrono::microseconds(kBandwidthPeriod));
}

void VpnServer::HandleVpnLoginResponse(
        transport::protobuf::Header& header,
        block::protobuf::BlockMessage& block_msg) try {
    auto& attr_res = block_msg.acc_attr_res();
    service::BandwidthInfoPtr bw_item_ptr = nullptr;
    VPNSVR_ERROR("HandleVpnLoginResponse coming: %s: %d", header.from_ip().c_str(), header.from_port());
    {
//         std::lock_guard<std::mutex> guard(account_map_mutex_);
        auto iter = account_map_.find(attr_res.account());
        if (iter != account_map_.end()) {
            bw_item_ptr = iter->second;
        }
    }
    if (attr_res.block().empty() && bw_item_ptr != nullptr) {
        if (bw_item_ptr->vip_timestamp == -100) {
            bw_item_ptr->vip_timestamp = -99;
        }
    }

    bft::protobuf::Block block;
    if (!block.ParseFromString(attr_res.block())) {
        return;
    }

    // TODO(): check block multi sign, this node must get election blocks
    std::string login_svr_id;
    uint64_t day_pay_timestamp = 0;
    uint64_t vip_tenons = 0;
    auto& tx_list = block.tx_list();
    for (int32_t i = tx_list.size() - 1; i >= 0; --i) {
        if (tx_list[i].attr_size() > 0) {
            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                if (tx_list[i].attr(attr_idx).key() == common::kUserPayForVpn &&
                        VpnServer::Instance()->VipCommitteeAccountValid(tx_list[i].to()) &&
                        bw_item_ptr != nullptr) {
                    day_pay_timestamp = block.timestamp();
                    vip_tenons = tx_list[i].amount();
                    bw_item_ptr->vpn_pay_for_height = block.height();
                }

                if (tx_list[i].attr(attr_idx).key() == common::kCheckVpnVersion) {
                    VPNSVR_ERROR("HandleVpnLoginResponse common::kCheckVpnVersion coming: %s: %d", header.from_ip().c_str(), header.from_port());
                    if (block.height() > vpn_version_last_height_) {
                        vpn_version_last_height_ = block.height();
                        auto str = tx_list[i].attr(attr_idx).value();
                        init::UpdateVpnInit::Instance()->SetVersionInfo(str);
                    }
                }
            }
        }

        if (!login_svr_id.empty()) {
            break;
        }
    }

    if (day_pay_timestamp == 0 || bw_item_ptr == nullptr) {
        return;
    }

    bw_item_ptr->pre_payfor_get_time = (std::chrono::steady_clock::now() +
            std::chrono::microseconds(kVipCheckPeriod));
    uint64_t day_msec = 24llu * 3600llu * 1000llu;
    uint32_t day_pay_for_vpn = day_pay_timestamp / day_msec;
    bw_item_ptr->vip_timestamp = day_pay_for_vpn;
    bw_item_ptr->vip_payed_tenon = vip_tenons;
} catch (std::exception& e) {
    VPNSVR_ERROR("receive get vip info catched error[%s]", e.what());
}

void VpnServer::CheckVersion() {
    SendGetAccountAttrLastBlock(
            common::kCheckVpnVersion,
            kCheckVersionAccount,
            vpn_version_last_height_);
    if (init::UpdateVpnInit::Instance()->GetVersion().empty()) {
        check_ver_tick_.CutOff(
            1000 * 1000,
            std::bind(&VpnServer::CheckVersion, VpnServer::Instance()));
    } else {
        check_ver_tick_.CutOff(
            10 * 1000 * 1000,
            std::bind(&VpnServer::CheckVersion, VpnServer::Instance()));
    }
}

void VpnServer::CheckAccountValid() {
    static const uint32_t kWaitingLogin = 10 * 1000 * 1000;
    service::BandwidthInfoPtr account_info = nullptr;
    while (bandwidth_queue_.pop(&account_info)) {
        if (account_info != nullptr) {
            auto iter = account_map_.find(account_info->account_id);
            if (iter != account_map_.end()) {
                continue;
            }
            account_info->join_time = std::chrono::steady_clock::now() +
                    std::chrono::microseconds(kWaitingLogin);
            account_info->down_bandwidth = kConnectInitBandwidth;
            account_map_[account_info->account_id] = account_info;
            SendClientUseBandwidth(
                    account_info->account_id,
                    5 * 1024);
        }
    }
// 
//     auto now_point = std::chrono::steady_clock::now();
//     for (auto iter = account_map_.begin(); iter != account_map_.end();) {
//         if ((iter->second->timeout + std::chrono::microseconds(kVpnClientTimeout + 10)) < now_point) {
//             SendClientUseBandwidth(
//                     iter->second->account_id,
//                     iter->second->up_bandwidth + iter->second->down_bandwidth);
//             iter->second->today_used_bandwidth = 0;
//             account_map_.erase(iter++);
//             continue;
//         }
// 
//         if ((iter->second->up_bandwidth + iter->second->down_bandwidth) >= kAddBandwidth) {
//             SendClientUseBandwidth(
//                     iter->second->account_id,
//                     iter->second->up_bandwidth + iter->second->down_bandwidth);
// 
//             if (iter->second->client_staking_time < now_point) {
//                 // transaction now with bandwidth
//                 uint32_t rand_band = std::rand() % iter->second->down_bandwidth;
//                 std::string gid;
//                 uint32_t rand_coin = 0;
//                 if (rand_band > 0u && rand_band <= 50u * 1024u * 1024u) {
//                     rand_coin = std::rand() % 6;
//                 }
// 
//                 if (rand_band > 50u * 1024u * 1024u && rand_band <= 100u * 1024u * 1024u) {
//                     rand_coin = std::rand() % 10;
//                 }
// 
//                 if (rand_band > 100u * 1024u * 1024u && rand_band <= 500u * 1024u * 1024u) {
//                     rand_coin = std::rand() % 15;
//                 }
// 
//                 if (rand_band > 500u * 1024u * 1024u) {
//                     rand_coin = std::rand() % 20;
//                 }
// 
//                 if (rand_coin > 3) {
//                     tenon::vpn::VpnServer::Instance()->staking_queue().push(
//                         std::make_shared<StakingItem>(iter->second->account_id, rand_coin));
//                 }
// 
//                 iter->second->client_staking_time = now_point + std::chrono::microseconds(kTransactionTimeout);
//             }
// 
//             iter->second->up_bandwidth = 0;
//             iter->second->down_bandwidth = 0;
//         }
// 
//         if (!iter->second->IsVip()) {
//             SendGetAccountAttrUsedBandwidth(iter->second->account_id);
//         }
// 
//         SendGetAccountAttrLastBlock(
//                 common::kUserPayForVpn,
//                 iter->second->account_id,
//                 iter->second->vpn_pay_for_height);
//         ++iter;
//     }
    bandwidth_tick_.CutOff(
            kStakingCheckingPeriod,
            std::bind(&VpnServer::CheckAccountValid, VpnServer::Instance()));
}

void VpnServer::StartMoreServer() {
    auto vpn_svr_dht = network::DhtManager::Instance()->GetDht(network::kVpnNetworkId);
    if (vpn_svr_dht == nullptr) {
        return;
    }

    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    std::vector<uint16_t> valid_port;
    for (int i = -1; i <= 1; ++i) {
        VPNSVR_ERROR("now create vpn server port: %d,. min: %d, max: %d",
            now_timestamp_days + i,
            common::GlobalInfo::Instance()->min_svr_port(),
            common::GlobalInfo::Instance()->max_svr_port());
        auto port = common::GetVpnServerPort(
                vpn_svr_dht->local_node()->dht_key(),
                now_timestamp_days + i,
                common::GlobalInfo::Instance()->min_svr_port(),
                common::GlobalInfo::Instance()->max_svr_port());
        if (started_port_set_.find(port) != started_port_set_.end()) {
            continue;
        }

        valid_port.push_back(port);
    }

    if (valid_port.empty()) {
        return;
    }

    for (uint32_t i = 0; i < valid_port.size(); ++i) {
        VPNSVR_ERROR("now start vpn server port: %d", valid_port[i]);
        std::shared_ptr<listen_ctx_t> listen_ctx_ptr = std::make_shared<listen_ctx_t>();
        if (StartTcpServer(
                common::GlobalInfo::Instance()->config_local_ip(),
                valid_port[i],
                listen_ctx_ptr.get()) == 0) {
            listen_ctx_ptr->vpn_port = valid_port[i];
            cork_dllist_init(&listen_ctx_ptr->svr_item->connections);
            last_listen_ptr_ = listen_ctx_ptr;
            listen_ctx_queue_.push_back(listen_ctx_ptr);
            started_port_set_.insert(valid_port[i]);
            VPNSVR_ERROR("success start vpn server port: %d", valid_port[i]);
        }
    }

    if (listen_ctx_queue_.size() >= common::kMaxRotationCount) {
        auto listen_item = listen_ctx_queue_.front();
        listen_ctx_queue_.pop_front();
        StopVpn(listen_item.get());
    }
}

void VpnServer::RotationServer() {
    StartMoreServer();
    new_vpn_server_tick_.CutOff(
            common::kRotationPeriod,
            std::bind(&VpnServer::RotationServer, VpnServer::Instance()));
}

user_ev_io_t* VpnServer::GetEvUserIo() {
//     uint32_t rand_idx = rand() % ev_udp_queue_.size();
    return ev_udp_queue_[valid_ev_io_idx_++ % ev_udp_queue_.size()];
}

uint16_t VpnServer::GetRoutePort(const std::string& ip) {
    if (valid_ev_port_idx_ > 10) {
        valid_ev_port_idx_ = -10;
    }

    auto timestamp_days = common::TimeUtils::TimestampDays() + valid_ev_port_idx_;
    uint16_t port = common::GetUdpRoutePort(
            common::Encode::HexDecode(remote_ip_dhtkey_map_[ip].dht_key),
            timestamp_days,
            remote_ip_dhtkey_map_[ip].min_port,
            remote_ip_dhtkey_map_[ip].max_port);
    valid_ev_port_idx_ += 1;
    return port;
}

void VpnServer::RoutingNodesHeartbeat() {
    for (uint32_t i = 0; i < routing_pos_vec_.size() && i < kMaxRelayRouteNode; ++i) {
        init::VpnServerNodePtr node_ptr = routing_nodes_[routing_pos_vec_[i]];
        if (node_ptr->ip != "113.17.169.103") {
            continue;
        }

        TcpRelayClientManager::Instance()->AddNewRouteServer(
                common::Encode::HexDecode(node_ptr->dht_key),
                node_ptr->ip,
                node_ptr->min_udp_port,
                node_ptr->max_udp_port);
    }

//     routing_nodes_hb_tick_.CutOff(
//             kRoutingNodeHeartbeatPeriod,
//             std::bind(&VpnServer::RoutingNodesHeartbeat, VpnServer::Instance()));
}

void VpnServer::ChooseRelayRouteNodes() {
    if (!common::GlobalInfo::Instance()->is_vlan_node()) {
        return;
    }

    init::UpdateVpnInit::Instance()->GetRouteSvrNodes(
            false,
            common::global_code_to_country_map[common::GlobalInfo::Instance()->country()],
            routing_nodes_);
    int idx = 0;
    for (auto iter = routing_nodes_.begin(); iter != routing_nodes_.end(); ++iter) {
        routing_pos_vec_.push_back(idx++);
    }

    if (routing_pos_vec_.size() > kMaxRelayRouteNode) {
        std::random_shuffle(routing_pos_vec_.begin(), routing_pos_vec_.end());
    }
}

int VpnServer::SendStreamData(server_t* server, remote_t* remote) {
    if (server->buf->len <= 0 || server->sid.ids.stream_id == 0) {
        return kVpnsvrError;
    }

    char tmp_data[102400];
    TcpRelayHead* head = (TcpRelayHead*)tmp_data;
    head->stream_len = (uint32_t)server->buf->len;
    head->server_id = server->sid.ids.id;
    static uint16_t message_id = 0;
    head->msg_id = message_id++;
    memcpy(tmp_data + sizeof(TcpRelayHead), server->buf->data, server->buf->len);
    if (vpn::TcpRelayClientManager::Instance()->SendStreamPacket(
            server->sid.ids.stream_id,
            server->sid.ids.id,
            tmp_data,
            server->buf->len + sizeof(TcpRelayHead),
            remote) != 0) {
        return kVpnsvrError;
    }

    return kVpnsvrSuccess;
}

void VpnServer::HandleHeartbeatResponse(
        user_ev_io_t* user_ev_io,
        transport::TransportHeader* trans_header,
        const struct sockaddr* addr) {
    if (trans_header->context_id == 0) {
        return;
    }

    struct sockaddr_in *sock = (struct sockaddr_in*)addr;
    char ip[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &sock->sin_addr, ip, sizeof(ip));
    int from_port = ntohs(sock->sin_port);
    std::string key = std::string(ip) + "_" + std::to_string(from_port);
    if (udp_user_data_map_.find(key) == udp_user_data_map_.end()) {
        vpn::UdpUserData* udp_user_data = (vpn::UdpUserData*)malloc(sizeof(vpn::UdpUserData));
        udp_user_data->id = trans_header->context_id;
        memcpy(udp_user_data->ip, ip, sizeof(udp_user_data->ip));
        udp_user_data->port = from_port;
        udp_user_data->user_ev_io = user_ev_io;
        udp_user_data_map_[key] = udp_user_data;
    }
}

vpn::UdpUserData* VpnServer::GetUdpUserData(const struct sockaddr* addr) {
    struct sockaddr_in *sock = (struct sockaddr_in*)addr;
    char ip[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &sock->sin_addr, ip, sizeof(ip));
    int from_port = ntohs(sock->sin_port);
    std::string key = std::string(ip) + "_" + std::to_string(from_port);
    auto iter = udp_user_data_map_.find(key);
    if (iter != udp_user_data_map_.end()) {
        return iter->second;
    }

    return NULL;
}

VlanConnection::~VlanConnection() {}

int VlanConnection::Connect(const std::string& ip, uint16_t port) {
    struct addrinfo info;
    struct sockaddr_storage storage;
    memset(&info, 0, sizeof(struct addrinfo));
    memset(&storage, 0, sizeof(struct sockaddr_storage));
    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
    size_t in_addr_len = sizeof(struct in_addr);
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(addr->sin_addr));
    addr->sin_port = htons(port);
    info.ai_family = AF_INET;
    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = IPPROTO_TCP;
    info.ai_addrlen = sizeof(struct sockaddr_in);
    info.ai_addr = (struct sockaddr *)addr;
    remote_ = VlanServerConnectToRoute(vpn::EvLoopManager::Instance()->loop(), &info);
    if (remote_ == NULL) {
        return 1;
    }

    remote_->reserve_buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    balloc(remote_->reserve_buf, SOCKET_BUF_SIZE * 1024);
    remote_->vlan_conn = this;
    remote_->real_remotes = new std::vector<remote_t*>();
    return 0;
}

bool VlanConnection::SendPacket(const char* data, uint32_t len, remote_t* real_remote) {
    if (remote_ == NULL) {
        return false;
    }

    buffer_t* buf = remote_->reserve_buf;
    if (buf->len + len >= SOCKET_BUF_SIZE * 1024) {
        return false;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    if (remote_->hold_to_send) {
        if (real_remote != NULL) {
            real_remote->hold_by_vlan_remote = true;
            remote_->real_remotes->push_back(real_remote);
            ev_io_stop(vpn::EvLoopManager::Instance()->loop(), &real_remote->recv_ctx->io);
        }
        return true;
    }

    int s = send(remote_->fd, buf->data, buf->len, 0);
    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            buf->idx = 0;
            remote_->hold_to_send = true;
            if (real_remote != NULL) {
                real_remote->hold_by_vlan_remote = true;
                remote_->real_remotes->push_back(real_remote);
                ev_io_stop(vpn::EvLoopManager::Instance()->loop(), &real_remote->recv_ctx->io);
            }
            ev_io_start(vpn::EvLoopManager::Instance()->loop(), &remote_->send_ctx->io);
        } else {
            ERROR("server_recv_send");
            if (real_remote != NULL) {
                CloseAndFreeRemote(vpn::EvLoopManager::Instance()->loop(), real_remote);
            }

            remote_->hold_by_valn_queue = false;
            CloseAndFreeRemote(vpn::EvLoopManager::Instance()->loop(), remote_);
            remote_ = NULL;
            return false;
        }
    } else if (s < static_cast<int>(buf->len)) {
        buf->idx = s;
        remote_->hold_to_send = true;
        if (real_remote != NULL) {
            real_remote->hold_by_vlan_remote = true;
            remote_->real_remotes->push_back(real_remote);
            ev_io_stop(vpn::EvLoopManager::Instance()->loop(), &real_remote->recv_ctx->io);
        }
        ev_io_start(vpn::EvLoopManager::Instance()->loop(), &remote_->send_ctx->io);
    } else {
        buf->len = 0;
        buf->idx = 0;
    }

    return true;
}

}  // namespace vpn

}  // namespace tenon