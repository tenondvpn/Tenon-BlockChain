#pragma once

#include <unordered_map>

#include "common/utils.h"

namespace tenon {

namespace root {

class ShardInfo {
public:
    ShardInfo();
    ~ShardInfo();

private:
    uint32_t network_id;
    uint32_t stake_sum;
    uint32_t overload;
    std::unordered_map<std::string, uint32_t> node_success_tx_count_;
    std::mutex node_success_tx_count_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ShardInfo);
};

typedef std::shared_ptr<ShardInfo> ShardInfoPtr;

};  // namespace root

};  // namespace root