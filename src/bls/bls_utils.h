#pragma once

#include <memory>
#include <unordered_map>

#include <libbls/bls/BLSPrivateKey.h>
#include <libbls/bls/BLSPrivateKeyShare.h>
#include <libbls/bls/BLSPublicKey.h>
#include <libbls/bls/BLSPublicKeyShare.h>
#include <libbls/tools/utils.h>
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

static const float kBlsMaxExchangeMembersRatio = 0.7f;  // 90%

struct MaxBlsMemberItem {
    MaxBlsMemberItem(uint32_t c, const common::Bitmap& b)
        : count(c), bitmap(b) {}
    uint32_t count;
    common::Bitmap bitmap;
};

struct BlsFinishItem {
    BlsFinishItem() {
        for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
            all_public_keys[i] = libff::alt_bn128_G2::zero();
        }
    }

    libff::alt_bn128_G2 all_public_keys[common::kEachShardMaxNodeCount];
    libff::alt_bn128_G1 all_bls_signs[common::kEachShardMaxNodeCount];
    libff::alt_bn128_G2 all_common_public_keys[common::kEachShardMaxNodeCount];
    uint32_t max_finish_count{ 0 };
    std::string max_finish_hash;
    std::unordered_map<std::string, std::shared_ptr<MaxBlsMemberItem>> max_bls_members;
    std::unordered_map<std::string, uint32_t> max_public_pk_map;
    std::unordered_map<std::string, libff::alt_bn128_G2> common_pk_map;
    std::vector<libff::alt_bn128_G1> verify_t_signs;
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
