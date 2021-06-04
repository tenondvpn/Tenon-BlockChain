#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"

#define CONGRESS_DEBUG(fmt, ...) TENON_DEBUG("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_INFO(fmt, ...) TENON_INFO("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_WARN(fmt, ...) TENON_WARN("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_ERROR(fmt, ...) TENON_ERROR("[root]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace root {

enum RootErrorCode {
    kRootSuccess = 0,
    kRootError = 1,
};

static const uint32_t kCongressTestNetworkShardId = 4u;
static const std::string kRootChainSingleBlockTxAddress = common::Encode::HexDecode("1000000000000000000000000000000000000001");

}  // namespace root

}  // namespace tenon
