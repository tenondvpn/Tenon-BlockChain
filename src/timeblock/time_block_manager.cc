#include "timeblock/time_block_manager.h"

#include <cstdlib>
#include "timeblock/time_block_utils.h"

namespace tenon {

namespace tmblock {

TimeBlockManager* TimeBlockManager::Instance() {
    static TimeBlockManager ins;
    return &ins;
}

uint64_t TimeBlockManager::LatestTimestamp() {
    return latest_time_block_tm_;
}

void TimeBlockManager::UpdateTimeBlock(
        uint64_t latest_time_block_height,
        uint64_t latest_time_block_tm) {
    latest_time_block_height_ = latest_time_block_height;
    latest_time_block_tm_ = latest_time_block_tm;
    latest_time_block_local_tm_ = common::TimeUtils::TimestampSeconds();
    std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
    latest_time_blocks_.push_back(latest_time_block_tm_);
    if (latest_time_blocks_.size() >= kTimeBlockAvgCount) {
        latest_time_blocks_.pop_front();
    }
}

bool TimeBlockManager::LeaderNewTimeBlockValid(uint64_t* new_time_block_tm) {
    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (now_tm - latest_time_block_local_tm_ >= kTimeBlockCreatePeriodSeconds) {
        std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
        // Correction time
        *new_time_block_tm = latest_time_block_tm_ +
            (now_tm - latest_time_block_local_tm_) +
            (latest_time_block_tm_ - latest_time_blocks_.front()) /
            (kTimeBlockCreatePeriodSeconds * kTimeBlockAvgCount);
        return true;
    }

    return false;
}

bool TimeBlockManager::BackupheckNewTimeBlockValid(uint64_t new_time_block_tm) {
    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (abs(new_time_block_tm - latest_time_block_tm_) < kTimeBlockTolerateSeconds) {
        return true;
    }

    return false;
}

}  // namespace tmblock

}  // namespace tenon