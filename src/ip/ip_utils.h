#pragma once

#include "common/utils.h"
#include "common/log.h"

#define IP_DEBUG(fmt, ...) TENON_DEBUG("[ip]" fmt, ## __VA_ARGS__)
#define IP_INFO(fmt, ...) TENON_INFO("[ip]" fmt, ## __VA_ARGS__)
#define IP_WARN(fmt, ...) TENON_WARN("[ip]" fmt, ## __VA_ARGS__)
#define IP_ERROR(fmt, ...) TENON_ERROR("[ip]" fmt, ## __VA_ARGS__)

namespace lego {

namespace ip {

enum IpErrorCode {
    kIpSuccess = 0,
    kIpError = 1,
};

static const uint8_t kInvalidCountryCode = 255u;

}  // namespace ip

}  // namespace lego
