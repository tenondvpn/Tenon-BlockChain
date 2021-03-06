#pragma once

#include "common/utils.h"
#include "common/log.h"

#define SUBS_DEBUG(fmt, ...) TENON_DEBUG("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_INFO(fmt, ...) TENON_INFO("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_WARN(fmt, ...) TENON_WARN("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_ERROR(fmt, ...) TENON_ERROR("[SUBS]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace subs {

enum SubsErrorCode {
    kSubsSuccess = 0,
    kSubsError = 1,
};

}  // namespace subs

}  // namespace tenon
