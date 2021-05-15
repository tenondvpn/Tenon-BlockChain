#pragma once

#include "common/utils.h"
#include "common/log.h"

#define NAT_DEBUG(fmt, ...) TENON_DEBUG("[nat]" fmt, ## __VA_ARGS__)
#define NAT_INFO(fmt, ...) TENON_INFO("[nat]" fmt, ## __VA_ARGS__)
#define NAT_WARN(fmt, ...) TENON_WARN("[nat]" fmt, ## __VA_ARGS__)
#define NAT_ERROR(fmt, ...) TENON_ERROR("[nat]" fmt, ## __VA_ARGS__)
