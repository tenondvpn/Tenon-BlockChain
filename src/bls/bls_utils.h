#pragma once

#include "common/bitmap.h"
#include "common/utils.h"
#include "common/log.h"
#include "common/limit_heap.h"

#define BLS_DEBUG(fmt, ...) TENON_DEBUG("[bls]" fmt, ## __VA_ARGS__)
#define BLS_INFO(fmt, ...) TENON_INFO("[bls]" fmt, ## __VA_ARGS__)
#define BLS_WARN(fmt, ...) TENON_WARN("[bls]" fmt, ## __VA_ARGS__)
#define BLS_ERROR(fmt, ...) TENON_ERROR("[bls]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace bls {

enum BlsErrorCode {
    kBlsSuccess = 0,
    kBlsError = 1,
};

struct MaxBlsMemberItem {
    MaxBlsMemberItem(uint32_t c, const common::Bitmap& b) : count(c), bitmap(b) {}
    uint32_t count;
    common::Bitmap bitmap;
};

}  // namespace bls

}  // namespace tenon
