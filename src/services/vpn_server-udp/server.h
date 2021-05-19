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
#include "ssr/crypto.h"
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

#include "common/utils.h"
#include "common/random.h"
#include "common/tick.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "common/time_utils.h"
#include "security/ecdh_create_key.h"
#include "security/public_key.h"
#include "network/network_utils.h"
#include "limit/tocken_bucket.h"
#include "init/update_vpn_init.h"

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
        account = tenon::network::GetAccountAddressByPublicKey(pubkey);
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

struct BandwidthInfo {
    BandwidthInfo(uint32_t up, uint32_t down, const std::string& acc_id, const std::string& plat)
            : up_bandwidth(up), down_bandwidth(down), account_id(acc_id) {
        timeout = std::chrono::steady_clock::now();
        client_staking_time = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kTransactionTimeout));
        pre_bandwidth_get_time = std::chrono::steady_clock::now();
        pre_payfor_get_time = std::chrono::steady_clock::now();
        if (plat == "ios") {
            client_platform = tenon::common::kIos;
        }

        if (plat == "and") {
            client_platform = tenon::common::kAndroid;
        }

        if (plat == "win") {
            client_platform = tenon::common::kWindows;
        }

        if (plat == "mac") {
            client_platform = tenon::common::kMac;
        }
        today_used_bandwidth = 0;
    }

    bool Valid() {
        if (vip_timestamp == -100) {
            return true;
        }

        if (IsVip()) {
            if (today_used_bandwidth <= tenon::init::UpdateVpnInit::Instance()->max_vip_bandwidth()) {
                return true;
            }
            return false;
        }

        if (today_used_bandwidth <= tenon::init::UpdateVpnInit::Instance()->max_free_bandwidth()) {
            return true;
        }
        return false;
    }

    bool ValidRoute() {
        if (vip_timestamp == -100) {
            return true;
        }

        if (IsVip()) {
            return true;
        }

        return false;
    }


    bool IsVip() {
        uint32_t now_day_timestamp = tenon::common::TimeUtils::TimestampDays();
        int32_t vip_days = vip_payed_tenon / tenon::common::kVpnVipMinPayfor;
        if (vip_days > 0 && ((vip_timestamp + vip_days + 1) >= now_day_timestamp)) {
            return true;
        }
        return false;
    }

    volatile uint32_t up_bandwidth{ 0 };
    volatile uint32_t down_bandwidth{ 0 };
    uint64_t today_used_bandwidth;
    std::chrono::steady_clock::time_point timeout;
    std::chrono::steady_clock::time_point client_staking_time;
    int32_t vip_timestamp{ -100 };
    uint64_t vip_payed_tenon{ 0 };
    std::string account_id;
    std::chrono::steady_clock::time_point join_time;
    std::chrono::steady_clock::time_point pre_bandwidth_get_time;
    std::chrono::steady_clock::time_point pre_payfor_get_time;
    uint64_t vpn_login_height{ 0 };
    uint64_t vpn_pay_for_height{ 0 };
    uint32_t client_platform{ tenon::common::kUnknown };
    tenon::limit::TockenBucket tocken_bucket_{
            tenon::common::GlobalInfo::Instance()->config_default_stream_limit() };
};
typedef std::shared_ptr<BandwidthInfo> BandwidthInfoPtr;

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

typedef struct server {
    int fd;
    int stage;
    int frag;

    buffer_t *buf;

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
    uint32_t id;
    bool freed;
    uint32_t msg_no;
    tenon::vpn::EndPoint* endpoint;
} server_t;

typedef struct query {
    server_t *server;
    char hostname[MAX_HOSTNAME_LEN];
} query_t;

typedef struct remote_ctx {
    ev_io io;
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
} remote_t;

#endif // _SERVER_H
