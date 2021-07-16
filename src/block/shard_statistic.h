#pragma once

#include <unordered_map>
#include <atomic>
#include <random>
#include <memory>

#include "common/utils.h"
#include "block/block_utils.h"
#include "bft/proto/bft.pb.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace block {

class ShardStatistic {
public:
    static ShardStatistic* Instance();
    void AddShardPoolStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item);
    uint32_t ValidPoolCount();
    void GetStatisticInfo(block::protobuf::StatisticInfo* statistic_info);
    void CreateStatisticTransaction();

private:
    ShardStatistic() {}
    ~ShardStatistic() {}

    std::atomic<uint64_t> latest_tm_height_{ 0 };
    std::atomic<uint64_t> latest_elect_height_{ 0 };
    std::atomic<uint32_t> pool_statistics_[common::kImmutablePoolSize + 1];
    std::shared_ptr<std::mt19937_64> g2_for_random_pool_{ nullptr };
    std::mutex pool_statistics_mutex_;
    common::Bitmap valid_pool_{ common::kImmutablePoolSize + 64 };
    std::atomic<uint32_t> all_tx_count_{ 0 };
    std::atomic<int32_t> elect_member_count_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ShardStatistic);
};

}  // namespace block

}  // namespace tenon
