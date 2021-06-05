#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"

#define TMBLOCK_DEBUG(fmt, ...) TENON_DEBUG("[tmblock]" fmt, ## __VA_ARGS__)
#define TMBLOCK_INFO(fmt, ...) TENON_INFO("[tmblock]" fmt, ## __VA_ARGS__)
#define TMBLOCK_WARN(fmt, ...) TENON_WARN("[tmblock]" fmt, ## __VA_ARGS__)
#define TMBLOCK_ERROR(fmt, ...) TENON_ERROR("[tmblock]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace tmblock {

enum RootErrorCode {
    kTimeBlockSuccess = 0,
    kTimeBlockError = 1,
};

static const uint64_t kTimeBlockCreatePeriodSeconds = 600llu;
static const uint64_t kTimeBlockTolerateSeconds = 60llu;
static const uint32_t kTimeBlockAvgCount = 6u;
static const std::string kAttrTimerBlock = "__tmblock_tmblock";

}  // namespace tmblock

}  // namespace tenon
