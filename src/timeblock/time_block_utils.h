#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"

#define CONGRESS_DEBUG(fmt, ...) TENON_DEBUG("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_INFO(fmt, ...) TENON_INFO("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_WARN(fmt, ...) TENON_WARN("[root]" fmt, ## __VA_ARGS__)
#define CONGRESS_ERROR(fmt, ...) TENON_ERROR("[root]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace tmblock {

enum RootErrorCode {
    kTimeBlockSuccess = 0,
    kTimeBlockError = 1,
};

static const uint64_t kTimeBlockCreatePeriodSeconds = 600llu;
static const uint64_t kTimeBlockTolerateSeconds = 60llu;
static const uint32_t kTimeBlockAvgCount = 6u;

}  // namespace tmblock

}  // namespace tenon
