#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/limit_heap.h"

#define VSS_DEBUG(fmt, ...) TENON_DEBUG("[vss]" fmt, ## __VA_ARGS__)
#define VSS_INFO(fmt, ...) TENON_INFO("[vss]" fmt, ## __VA_ARGS__)
#define VSS_WARN(fmt, ...) TENON_WARN("[vss]" fmt, ## __VA_ARGS__)
#define VSS_ERROR(fmt, ...) TENON_ERROR("[vss]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace vss {

enum VssErrorCode {
    kVssSuccess = 0,
    kVssError = 1,
};

static const uint32_t kVssRandomSplitCount = 7u;
static const uint32_t kVssRandomduplicationCount = 7u;
// left 60 seconds for each nodes valid
static const uint64_t kVssAllPeriodSeconds = common::kTimeBlockCreatePeriodSeconds - 60;
static const uint64_t kVssFirstPeriodTimeout = kVssAllPeriodSeconds / 3;
static const uint64_t kVssSecondPeriodTimeout = 2 * kVssAllPeriodSeconds / 3;
static const uint64_t kVssThirdPeriodTimeout = kVssAllPeriodSeconds;

}  // namespace vss

}  // namespace tenon
