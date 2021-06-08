#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <atomic>

#include "common/hash.h"
#include "common/encode.h"
#include "common/utils.h"
#include "common/log.h"
#include "security/public_key.h"
#include "security/signature.h"
#include "dht/proto/dht.pb.h"

#define DHT_DEBUG(fmt, ...) TENON_DEBUG("[dht]" fmt, ## __VA_ARGS__)
#define DHT_INFO(fmt, ...) TENON_INFO("[dht]" fmt, ## __VA_ARGS__)
#define DHT_WARN(fmt, ...) TENON_WARN("[dht]" fmt, ## __VA_ARGS__)
#define DHT_ERROR(fmt, ...) TENON_ERROR("[dht]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace dht {

class BaseDht;

enum DhtErrorCode {
    kDhtSuccess = 0,
    kDhtError = 1,
    kDhtInvalidNat = 2,
    kDhtNodeJoined = 3,
    kDhtInvalidBucket = 4,
    kDhtDesInvalid = 5,
    kDhtIpInvalid = 6,
    kDhtKeyInvalid = 7,
    kDhtClientMode = 8,
    kNodeInvalid = 9,
    kDhtKeyHashError = 10,
    kDhtGetBucketError = 11,
    kDhtMaxNeiborsError = 12,
};

enum BootstrapTag {
    kBootstrapNoInit = 0,
    kBootstrapInit = 1,
    kBootstrapInitWithConfNodes = 2,
};

enum NatType {
    kNatTypeUnknown = 0,
    kNatTypeFullcone = 1,
    kNatTypeAddressLimit = 2,
    kNatTypePortLimit = 3,
};

static const uint32_t kDhtNearestNodesCount = 16u;
static const uint32_t kDhtMinReserveNodes = 4u;
static const uint32_t kDhtKeySize = 32u;
static const uint32_t kDhtMaxNeighbors = kDhtKeySize * 8 + kDhtNearestNodesCount;
static const uint32_t kRefreshNeighborsCount = 32u;
static const uint32_t kRefreshNeighborsDefaultCount = 32u;
static const uint32_t kRefreshNeighborsBloomfilterBitCount = 4096u;
static const uint32_t kRefreshNeighborsBloomfilterHashCount = 11u;
static const uint32_t kHeartbeatDefaultAliveTimes = 3u;

struct Node {
    uint64_t id_hash{ 0 };
    uint64_t dht_key_hash{ 0 };
    int32_t bucket{ 0 };
    int32_t nat_detection_times{ 0 };
    int32_t nat_type{ 0 };
    int32_t heartbeat_times{ 0 };
    bool client_mode{ false };
    uint16_t public_port{ 0 };
    uint16_t local_port{ 0 };
    bool public_node{ true };
    bool first_node{ false };
    std::atomic<uint32_t> heartbeat_send_times{ 0 };
    std::atomic<uint32_t> heartbeat_alive_times{ kHeartbeatDefaultAliveTimes };
    uint16_t min_svr_port;
    uint16_t max_svr_port;
    uint16_t min_route_port;
    uint16_t max_route_port;
    uint16_t min_udp_port;
    uint16_t max_udp_port;
    uint32_t node_weight;
    std::string join_com;

    Node() {};
    Node(const Node& other) {
        id_ = other.id_;
        id_hash = other.id_hash;
        dht_key_ = other.dht_key_;
        dht_key_hash = other.dht_key_hash;
        nat_type = other.nat_type;
        client_mode = other.client_mode;
        public_ip_ = other.public_ip_;
        public_port = other.public_port;
        local_ip_ = other.local_ip_;
        local_port = other.local_port;
        public_node = other.public_node;
        pubkey_str_ = other.pubkey_str_;
        min_svr_port = other.min_svr_port;
        max_svr_port = other.max_svr_port;
        min_route_port = other.min_route_port;
        max_route_port = other.max_route_port;
        min_udp_port = other.min_udp_port;
        max_udp_port = other.max_udp_port;
        node_weight = other.node_weight;
        node_tag_ = other.node_tag_;
    }

    Node(const std::string& in_id,
        const std::string& in_dht_key,
        const std::string& in_public_ip,
        uint16_t in_public_port,
        const std::string& in_pubkey_str,
        const std::string& node_tag) {
        id_ = in_id;
        id_hash = common::Hash::Hash64(in_id);
        dht_key_ = in_dht_key;
        dht_key_hash = common::Hash::Hash64(in_dht_key);
        nat_type = kNatTypeFullcone;
        public_ip_ = in_public_ip;
        public_port = in_public_port;
        local_ip_ = in_public_ip;
        local_port = in_public_port;
        public_node = true;
        pubkey_str_ = in_pubkey_str;
        node_tag_ = node_tag;
    }

    Node(
        const std::string& in_id,
        const std::string& in_dht_key,
        int32_t in_nat_type,
        bool in_client_mode,
        const std::string& in_public_ip,
        uint16_t in_public_port,
        const std::string& in_local_ip,
        uint16_t in_local_port,
        const std::string& in_pubkey_str,
        const std::string& node_tag) {
        id_ = in_id;
        id_hash = common::Hash::Hash64(in_id);
        dht_key_ = in_dht_key;
        dht_key_hash = common::Hash::Hash64(in_dht_key);
        nat_type = in_nat_type;
        client_mode = in_client_mode;
        public_ip_ = in_public_ip;
        public_port = in_public_port;
        local_ip_ = in_local_ip;
        local_port = in_local_port;
        if (public_ip_ == local_ip_) {
            public_node = true;
        }

        pubkey_str_ = in_pubkey_str;
        node_tag_ = node_tag;
    }

    const std::string& dht_key() {
        return dht_key_;
    }

    void set_dht_key(const std::string& dht_key) {
        dht_key_ = dht_key;
    }

    const std::string& id() {
        return id_;
    }

    const std::string& public_ip() {
        return public_ip_;
    }

    void set_public_ip(const std::string& public_ip) {
        public_ip_ = public_ip;
    }

    void set_node_tag(const std::string& node_tag) {
        node_tag_ = node_tag;
    }

    const std::string& pubkey_str() {
        return pubkey_str_;
    }

    void set_pubkey(const std::string& pubkey) {
        pubkey_str_ = pubkey;
    }

    const std::string& local_ip() {
        return local_ip_;
    }

    const std::string& node_tag() {
        return node_tag_;
    }

private:
    std::string id_;
    std::string dht_key_;
    std::string public_ip_;
    std::string local_ip_;
    std::string pubkey_str_;
    std::string sign_str_;
    std::string node_tag_;
};

typedef std::shared_ptr<Node> NodePtr;
typedef std::function<void(BaseDht* dht, const protobuf::DhtMessage& dht_msg)> BootstrapResponseCallback;
typedef std::function<void(const NodePtr& node)> NewNodeJoinCallback;

}  // namespace dht

}  // namespace tenon
