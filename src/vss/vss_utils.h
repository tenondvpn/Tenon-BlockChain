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

enum VssMessageType {
    kVssRandomHash = 1,
    kVssRandom = 2,
    kVssFinalRandom = 3,
};

static const int32_t kVssRandomSplitCount = 3u;
static const uint32_t kVssRandomduplicationCount = 7u;
static const int64_t kVssCheckPeriodTimeout = 3000000ll;
// Avoid small differences in time between different machines leading to cheating
static const uint32_t kVssTimePeriodOffsetSeconds = 3u;
static const uint32_t kHandleMessageVssTimePeriodOffsetSeconds = 1u;
// left 60 seconds for each nodes valid
static const uint64_t kVssAllPeriodSeconds = common::kTimeBlockCreatePeriodSeconds - 60;
static const uint64_t kVssFirstPeriodTimeout = kVssAllPeriodSeconds / 3;
static const uint64_t kVssSecondPeriodTimeout = 2 * kVssAllPeriodSeconds / 3;
static const uint64_t kVssThirdPeriodTimeout = kVssAllPeriodSeconds;

}  // namespace vss

}  // namespace tenon
