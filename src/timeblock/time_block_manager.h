#pragma once

#include <atomic>
#include <mutex>
#include <deque>

#include "bft/proto/bft.pb.h"
#include "common/utils.h"
#include "common/time_utils.h"
#include "common/tick.h"
#include "dht/dht_utils.h"
#include "transport/proto/transport.pb.h"

namespace tenon {

namespace tmblock {

class TimeBlockManager {
public:
    static TimeBlockManager* Instance();
    uint64_t LatestTimestamp();
    uint64_t LatestTimestampHeight();
    void UpdateTimeBlock(
        uint64_t latest_time_block_height,
        uint64_t lastest_time_block_tm,
        uint64_t vss_random);
    bool LeaderNewTimeBlockValid(uint64_t* new_time_block_tm);
    bool BackupheckNewTimeBlockValid(uint64_t new_time_block_tm);
    int LeaderCreateTimeBlockTx(transport::protobuf::Header* msg);
    int BackupCheckTimeBlockTx(const bft::protobuf::TxInfo& tx_info);

private:
    TimeBlockManager();
    ~TimeBlockManager();

    void CreateTimeBlockTx();
    bool ThisNodeIsLeader(int32_t* pool_mod_num);
    void CheckBft();
    void BroadcastTimeBlock();
    void CreateTmBroadcastMessage(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg);

    std::atomic<uint64_t> latest_time_block_height_{ 0 };
    std::atomic<uint64_t> latest_time_block_tm_{ 0 };
    std::deque<uint64_t> latest_time_blocks_;
    std::mutex latest_time_blocks_mutex_;
    common::Tick create_tm_block_tick_;
    common::Tick check_bft_tick_;
    common::Tick broadcast_tm_tick_;

    DISALLOW_COPY_AND_ASSIGN(TimeBlockManager);
};

}  // namespace tmblock

}  // namespace tenon