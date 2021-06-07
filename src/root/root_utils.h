#pragma once

#include <unordered_map>

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"

#define ROOT_DEBUG(fmt, ...) TENON_DEBUG("[root]" fmt, ## __VA_ARGS__)
#define ROOT_INFO(fmt, ...) TENON_INFO("[root]" fmt, ## __VA_ARGS__)
#define ROOT_WARN(fmt, ...) TENON_WARN("[root]" fmt, ## __VA_ARGS__)
#define ROOT_ERROR(fmt, ...) TENON_ERROR("[root]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace root {

enum RootErrorCode {
    kRootSuccess = 0,
    kRootError = 1,
};

static const uint32_t kCongressTestNetworkShardId = 4u;
static const std::string kRootChainSingleBlockTxAddress = common::Encode::HexDecode(common::StringUtil::Format("1000000000000000000000000000000000000%3d", common::kRootChainPoolIndex));

}  // namespace root

}  // namespace tenon
