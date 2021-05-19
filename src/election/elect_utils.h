#pragma once

#include "common/utils.h"
#include "common/log.h"

#define ELECT_DEBUG(fmt, ...) TENON_DEBUG("[elect]" fmt, ## __VA_ARGS__)
#define ELECT_INFO(fmt, ...) TENON_INFO("[elect]" fmt, ## __VA_ARGS__)
#define ELECT_WARN(fmt, ...) TENON_WARN("[elect]" fmt, ## __VA_ARGS__)
#define ELECT_ERROR(fmt, ...) TENON_ERROR("[elect]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace elect {

enum ElectErrorCode {
    kElectSuccess = 0,
    kElectError = 1,
    kElectJoinUniversalError = 2,
    kElectJoinShardFailed = 3,
    kElectNoBootstrapNodes = 4,
    kElectNetworkJoined = 5,
    kElectNetworkNotJoined = 6,
};

static const uint32_t kElectBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kElectBroadcastStopTimes = 2u;
static const uint32_t kElectHopLimit = 5u;
static const uint32_t kElectHopToLayer = 2u;
static const uint32_t kElectNeighborCount = 7u;

}  // namespace elect

}  // namespace tenon
