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
    void GetStatisticInfo(uint64_t timeblock_height, block::protobuf::StatisticInfo* statistic_info);

private:
    ShardStatistic() {
        for (uint32_t i = 0; i < kStatisticMaxCount; ++i) {
            statistic_items_[i] = std::make_shared<StatisticItem>();
        }
    }

    ~ShardStatistic() {}
    int LoadBlocksUtilLatestStatisticBlock();
    void CreateStatisticTransaction(uint64_t timeblock_height);

    std::shared_ptr<StatisticItem> statistic_items_[kStatisticMaxCount];

    DISALLOW_COPY_AND_ASSIGN(ShardStatistic);
};

}  // namespace block

}  // namespace tenon
