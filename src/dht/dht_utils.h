#pragma once

#include "common/utils.h"
#include "common/log.h"

#define DHT_DEBUG(fmt, ...) TENON_DEBUG("[dht]" fmt, ## __VA_ARGS__)
#define DHT_INFO(fmt, ...) TENON_INFO("[dht]" fmt, ## __VA_ARGS__)
#define DHT_WARN(fmt, ...) TENON_WARN("[dht]" fmt, ## __VA_ARGS__)
#define DHT_ERROR(fmt, ...) TENON_ERROR("[dht]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace dht {

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

static const uint32_t kDhtNearestNodesCount = 16u;
static const uint32_t kDhtMinReserveNodes = 4u;
static const uint32_t kDhtKeySize = 32u;
static const uint32_t kDhtMaxNeighbors = kDhtKeySize * 8 + kDhtNearestNodesCount;
static const uint32_t kRefreshNeighborsCount = 32u;
static const uint32_t kRefreshNeighborsDefaultCount = 32u;
static const uint32_t kRefreshNeighborsBloomfilterBitCount = 4096u;
static const uint32_t kRefreshNeighborsBloomfilterHashCount = 11u;
static const uint32_t kHeartbeatDefaultAliveTimes = 3u;

}  // namespace dht

}  // namespace tenon
