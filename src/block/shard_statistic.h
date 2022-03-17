#pragma once

#include <unordered_map>
#include <atomic>
#include <random>
#include <memory>

#include "common/utils.h"
#include "common/bitmap.h"
#include "common/thread_safe_queue.h"
#include "common/tick.h"
#include "block/block_utils.h"
#include "bft/proto/bft.pb.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace block {

class ShardStatistic {
public:
    static ShardStatistic* Instance();
    void AddStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item);
    void GetStatisticInfo(
        uint64_t timeblock_height,
        block::protobuf::StatisticInfo* statistic_info);

private:
    ShardStatistic() {
        for (uint32_t i = 0; i < kStatisticMaxCount; ++i) {
            statistic_items_[i] = std::make_shared<StatisticItem>();
        }
    }

    ~ShardStatistic() {}
    void CreateStatisticTransaction(uint64_t timeblock_height);
    void NormalizePoints(
        uint64_t elect_height,
        std::unordered_map<int32_t, std::shared_ptr<common::Point>>& leader_lof_map);

    static const uint32_t kLofRation = 3u;
    static const uint32_t kLofMaxNodes = kLofRation * 3 / 2;

    std::shared_ptr<StatisticItem> statistic_items_[kStatisticMaxCount];
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(ShardStatistic);
};

}  // namespace block

}  // namespace tenon
