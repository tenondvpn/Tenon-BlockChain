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
    uint64_t balance;
    uint64_t tx_count;
    uint64_t heartbeat_success_count;
    uint64_t heartbeat_fail_count;
};

typedef std::shared_ptr<ElectNodeDetail> NodeDetailPtr;

};  // namespace elect

};  // namespace tenon