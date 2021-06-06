#pragma once

#include <atomic>
#include <mutex>
#include <deque>

#include "common/utils.h"
#include "common/time_utils.h"
#include "transport/proto/transport.pb.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace tmblock {

class TimeBlockManager {
public:
    static TimeBlockManager* Instance();
    uint64_t LatestTimestamp();
    void UpdateTimeBlock(uint64_t latest_time_block_height, uint64_t lastest_time_block_tm);
    bool LeaderNewTimeBlockValid(uint64_t* new_time_block_tm);
    bool BackupheckNewTimeBlockValid(uint64_t new_time_block_tm);
    int LeaderCreateTimeBlockTx(transport::protobuf::Header* msg);
    int BackupCheckTimeBlockTx(const bft::protobuf::TxInfo& tx_info);

private:
    TimeBlockManager() {}
    ~TimeBlockManager() {}

    std::atomic<uint64_t> latest_time_block_height_{ 0 };
    std::atomic<uint64_t> latest_time_block_tm_{ 0 };
    std::deque<uint64_t> latest_time_blocks_;
    std::mutex latest_time_blocks_mutex_;

    DISALLOW_COPY_AND_ASSIGN(TimeBlockManager);
};

}  // namespace tmblock

}  // namespace tenon