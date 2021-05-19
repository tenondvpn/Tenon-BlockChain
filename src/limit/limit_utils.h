#pragma once

#include "common/utils.h"
#include "common/log.h"

#define LIMIT_DEBUG(fmt, ...) TENON_DEBUG("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_INFO(fmt, ...) TENON_INFO("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_WARN(fmt, ...) TENON_WARN("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_ERROR(fmt, ...) TENON_ERROR("[limit]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace limit {

enum LimitErrorCode {
    kLimitSuccess = 0,
    kLimitError = 1,
};

}  // namespace limit

}  // namespace tenon
