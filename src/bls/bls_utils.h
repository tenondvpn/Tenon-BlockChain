#pragma once

#include <memory>
#include <unordered_map>

#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>
#include <dkg/dkg.h>

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
    MaxBlsMemberItem(uint32_t c, const common::Bitmap& b, const libff::alt_bn128_G2& cpk)
        : count(c), bitmap(b), common_public_key(cpk) {}
    uint32_t count;
    common::Bitmap bitmap;
    libff::alt_bn128_G2 common_public_key;
};

struct BlsFinishItem {
    libff::alt_bn128_G2 all_public_keys[common::kEachShardMaxNodeCount];
    uint32_t max_finish_count{ 0 };
    std::string max_finish_hash;
    std::unordered_map<std::string, std::shared_ptr<MaxBlsMemberItem>> max_bls_members;
    std::unordered_map<std::string, uint32_t> max_public_pk_map;
};

typedef std::shared_ptr<BlsFinishItem> BlsFinishItemPtr;

static inline bool IsValidBigInt(const std::string& big_int) {
    for (size_t i = 0; i < big_int.size(); ++i)
    {
        if (big_int[i] >= '0' && big_int[i] <= '9') {
            continue;
        }

        return false;
    }

    return true;
}
}  // namespace bls

}  // namespace tenon
