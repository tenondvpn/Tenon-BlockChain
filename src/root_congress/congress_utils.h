#pragma once

#include "common/utils.h"
#include "common/log.h"

#define CONGRESS_DEBUG(fmt, ...) TENON_DEBUG("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_INFO(fmt, ...) TENON_INFO("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_WARN(fmt, ...) TENON_WARN("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_ERROR(fmt, ...) TENON_ERROR("[congress]" fmt, ## __VA_ARGS__)

namespace lego {

namespace congress {

enum CongressErrorCode {
    kCongressSuccess = 0,
    kCongressError = 1,
};

static const uint32_t kCongressTestNetworkShardId = 4u;

}  // namespace congress

}  // namespace lego
