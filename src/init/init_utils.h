#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"

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

static const std::string kGenesisElectPrikeyEncryptKey = common::Encode::HexDecode(
    "17dfdd4d49509691361225e9059934675dea440d123aa8514441aa6788354016");

}  // namespace init

}  // namespace tenon
