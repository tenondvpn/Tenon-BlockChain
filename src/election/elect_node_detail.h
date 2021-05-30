#pragma once

#include <memory>

#include "common/utils.h"
#include "common/user_property_key_define.h"

namespace tenon {

namespace elect {

struct ElectNodeDetail {
    std::string id;
    std::string public_key;
    std::string public_ip;
    uint16_t public_port;
    std::string dht_key;
    uint64_t balance{ 0 };
    uint64_t tx_count{ 0 };
    std::chrono::steady_clock::time_point join_tm{ std::chrono::steady_clock::now() };
    std::map<uint64_t, uint32_t> heatbeat_succ_count;
    std::map<uint64_t, uint32_t> heatbeat_fail_count;
    std::mutex heartbeat_mutex;

    bool operator() (const ElectNodeDetail& left, const ElectNodeDetail& right) {
        return left.id < right.id;
    }
};

typedef std::shared_ptr<ElectNodeDetail> NodeDetailPtr;

inline static bool ElectNodeCompare(
        const NodeDetailPtr& left,
        const NodeDetailPtr& right) {
    return left->id < right->id;
}

};  // namespace elect

};  // namespace tenon