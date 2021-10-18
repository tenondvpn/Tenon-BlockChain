/*
 * server.h - Define shadowsocks server's buffers and callbacks
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _SERVER_H
#define _SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libcork/ds.h>
#include <time.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#ifdef __MINGW32__
#include "winsock.h"
#endif
#include "uv/uv.h"

#include "ssr/netutils.h"
#include "ssr/jconf.h"
#include "ssr/resolv.h"
#include <libcork/core.h>
#include "kcp/ikcp.h"
#include "ssr/common.h"
#ifdef __cplusplus
}
#endif

#include <memory>
#include <string>
#include <atomic>
#include <unordered_map>
#include <deque>

#include "common/utils.h"
#include "common/random.h"
#include "common/tick.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "common/time_utils.h"
#include "security/ecdh_create_key.h"
#include "security/public_key.h"
#include "tnet/tcp_connection.h"
#include "network/network_utils.h"
#include "limit/tocken_bucket.h"
#include "init/update_vpn_init.h"
#include "security/secp256k1.h"

static const uint32_t kPeerTimeout = 30 * 1000 * 1000;  // 30s
static const int64_t kTransactionTimeout = 1ll * 1000ll * 1000ll;  // 1 s
static const uint32_t kMaxBandwidthFreeUse = 2048u * 1024u * 1024u;

namespace tenon {

namespace vpn {

class EndPoint;

}

}

struct PeerInfo {
    PeerInfo(const std::string& pub, const std::string& mtd)
            : pubkey(pub), method(mtd) {}

    bool init() {
        sec_num = tenon::common::Random::RandomInt32();
        account = tenon::security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey);
        tenon::security::PublicKey pub_key;
        if (pub_key.Deserialize(pubkey) != 0) {
            return false;
        }

        auto res = tenon::security::EcdhCreateKey::Instance()->CreateKey(pub_key, seckey);
        if (res != tenon::security::kSecuritySuccess) {
            return false;
        }

        seckey = tenon::common::Encode::HexEncode(seckey);
        timeout = std::chrono::steady_clock::now() + std::chrono::microseconds(kPeerTimeout);
        crypto = crypto_init(seckey.c_str(), NULL, method.c_str());
        if (crypto == NULL) {
            return false;
        }

        return true;
    }
    std::string pubkey;
    std::string seckey;
    int32_t sec_num;
    std::string account;
    std::chrono::steady_clock::time_point timeout;
    crypto_t* crypto;
    std::string method;
};

struct StakingItem {
    StakingItem(const std::string& t, uint64_t count) : to(t), amount(count) {}
    std::string to;
    uint64_t amount;
};
typedef std::shared_ptr<StakingItem> StakingItemPtr;

typedef struct server_item {
    struct cork_dllist connections;
} server_item_t;

typedef struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    char *iface;
    struct ev_loop *loop;
    server_item_t* svr_item;
    std::shared_ptr<std::thread> thread_ptr; 
    ev_async async_watcher;
    uint16_t vpn_port;
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server *server;
} server_ctx_t;

#ifdef USE_NFCONNTRACK_TOS

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

struct dscptracker {
    struct nf_conntrack *ct;
    long unsigned int mark;
    unsigned int dscp;
    unsigned int packet_count;
};

#endif

struct query;
struct user_udp_t;

enum ServerType {
    kClientWlanServer = 0,
    kClientVlanServer = 1,
    kRemoteVlanServer = 2,
};

union ServerKey {
    struct {
        uint32_t id;
        uint32_t stream_id;
    } ids;
    uint64_t key;
};

typedef struct server {
    int fd;
    int stage;
    int frag;
    uint32_t id;
    //     buffer_t *header_buf;
    ServerKey sid;
    uint32_t client_id;
    buffer_t *buf;
    buffer_t *to_client_buf;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    struct remote *remote;
    struct query *query;
    struct cork_dllist_item entries;
    PeerInfo* client_ptr;
    server_item_t* svr_item;
    uint8_t country_code;
#ifdef USE_NFCONNTRACK_TOS
    struct dscptracker *tracker;
#endif
    bool freed;
    uint32_t msg_no;
    ev_io *w;
    std::deque<server*>* remote_vlan_client_queue;
    server* remote_vlan_client;
    uint32_t server_type;
    char vlan_key[64];
    buffer_t* vlan_local_buff;
    uint32_t vlan_local_sum_length;
    uint32_t vlan_local_prev_pkt_length;
    uint32_t vlan_prev_server_id;
    bool called_free;
    bool is_in_queue;
    uint32_t remote_vlan_client_used_count;
    std::deque<server*>* to_remote_servers;
    uint32_t in_to_remote_servers_count;
    buffer_t *reserve_buf;
    bool hold_to_send;
} server_t;

typedef struct query {
    server_t *server;
    char hostname[MAX_HOSTNAME_LEN];
} query_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif
    buffer_t *buf;
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    bool freed;
    uint32_t id;
    void* vlan_conn;
    std::vector<remote*>* real_remotes;
    buffer_t *reserve_buf;
    bool hold_to_send;
    bool hold_by_vlan_remote;
    bool hold_by_valn_queue;
    bool hold_valn_to_internet;
} remote_t;

#endif // _SERVER_H
