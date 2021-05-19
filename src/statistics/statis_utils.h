#pragma once

#include <type_traits>
#include <string>

#include "common/utils.h"
#include "common/log.h"
#include "common/hash.h"

#define STATIS_DEBUG(fmt, ...) TENON_DEBUG("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_INFO(fmt, ...) TENON_INFO("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_WARN(fmt, ...) TENON_WARN("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_ERROR(fmt, ...) TENON_ERROR("[statis]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace statis {

enum StatisErrorCode {
    kStatisSuccess = 0,
    kStatisError = 1,
};

struct AccountBalance {
    int64_t balance;
    char account_id[32];
};

bool operator<(AccountBalance& lhs, AccountBalance& rhs);
bool operator==(const AccountBalance& lhs, const AccountBalance& rhs);

}  // namespace statis

}  // namespace tenon

namespace std {
    template<>
    struct hash<tenon::statis::AccountBalance> {
        size_t operator()(const tenon::statis::AccountBalance& _Keyval) const noexcept {
            std::string key(_Keyval.account_id, sizeof(_Keyval.account_id));
            return tenon::common::Hash::Hash32(key);
        }
    };
}

namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const tenon::statis::AccountBalance& val);

}  // namespace common

}  // namespace tenon
