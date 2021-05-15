#pragma once

#include "common/utils.h"
#include "common/log.h"

#define VPNROUTE_DEBUG(fmt, ...) TENON_DEBUG("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_INFO(fmt, ...) TENON_INFO("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_WARN(fmt, ...) TENON_WARN("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_ERROR(fmt, ...) TENON_ERROR("[vpnrouteroute]" fmt, ## __VA_ARGS__)

namespace lego {

namespace vpnroute {

enum VpnRouteErrorCode {
    kVpnRouteSuccess = 0,
    kVpnRouteError = 1,
};

}  // namespace vpnroute

}  // namespace lego
