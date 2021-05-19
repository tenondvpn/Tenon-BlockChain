#pragma once

#include "common/utils.h"
#include "common/log.h"

#define INIT_DEBUG(fmt, ...) TENON_DEBUG("[init]" fmt, ## __VA_ARGS__)
#define INIT_INFO(fmt, ...) TENON_INFO("[init]" fmt, ## __VA_ARGS__)
#define INIT_WARN(fmt, ...) TENON_WARN("[init]" fmt, ## __VA_ARGS__)
#define INIT_ERROR(fmt, ...) TENON_ERROR("[init]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace init {

enum InitErrorCode {
    kInitSuccess = 0,
    kInitError = 1,
};

}  // namespace init

}  // namespace tenon
