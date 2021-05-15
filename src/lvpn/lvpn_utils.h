#pragma once

#include "common/utils.h"
#include "common/log.h"

#define LVPN_DEBUG(fmt, ...) TENON_DEBUG("[lvpn]" fmt, ## __VA_ARGS__)
#define LVPN_INFO(fmt, ...) TENON_INFO("[lvpn]" fmt, ## __VA_ARGS__)
#define LVPN_WARN(fmt, ...) TENON_WARN("[lvpn]" fmt, ## __VA_ARGS__)
#define LVPN_ERROR(fmt, ...) TENON_ERROR("[lvpn]" fmt, ## __VA_ARGS__)

namespace lego {

namespace lvpn {

enum LvpnErrorCode {
    kLvpnSuccess = 0,
    kLvpnError = 1,
};

}  // namespace lvpn

}  // namespace lego
