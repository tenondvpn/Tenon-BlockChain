#pragma once

#include "common/utils.h"
#include "common/string_utils.h"
#include "common/thread_safe_queue.h"
#include "common/tick.h"
#include "db/dict.h"
#include "db/db.h"
#include "block/block_utils.h"
#include "block/proto/block.pb.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace block {

class DbPoolInfo {
public:
    DbPoolInfo(uint32_t pool_index);
    ~DbPoolInfo();
    int InitWithGenesisBlock();
    int SetHash(const std::string& hash, db::DbWriteBach& db_batch);
    int GetHash(std::string* hash);
    int SetHeight(uint64_t height, db::DbWriteBach& db_batch);
    int GetHeight(uint64_t* height);
    int SetTimeBlockHeight(
        uint64_t tmblock_height,
        uint64_t block_height,
        db::DbWriteBach& db_batch);
    int GetTimeBlockHeight(uint64_t* height, uint64_t* block_height);
    int GetLastBlockInfo(uint64_t* block_height, uint64_t* block_tm, uint32_t* pool_index);
    std::string GetBaseAddr();
    void AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_ptr);
    void SatisticBlock();
    int GetStatisticInfo(block::protobuf::StatisticInfo* statistic_info);

private:
    int AddStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item);
    int LoadBlocksUtilLatestStatisticBlock();
    void TickSatisticBlock();

    static const uint32_t kUpdateStatisticPeriod = 10000lu;

    std::string dict_key_;
    std::string hash_;
    std::string last_block_str_;
    std::mutex hash_mutex_;
    std::string base_addr_;
    std::mutex base_addr_mutex_;
    std::atomic<uint64_t> height_{ common::kInvalidUint64 };
    std::atomic<uint32_t> pool_index_{ common::kInvalidUint32 };
    bft::protobuf::Block last_block_;
    std::atomic<uint64_t> prev_tmblock_height_{ common::kInvalidUint64 };
    std::atomic<uint64_t> prev_tmblock_with_pool_height_{ common::kInvalidUint64 };
    uint64_t max_time_block_height_{ 0 };
    std::mutex statistic_for_tmblock_mutex_;
    std::map<uint64_t, StatisticItem> statistic_for_tmblock_;
    common::ThreadSafeQueue<std::shared_ptr<bft::protobuf::Block>> server_bandwidth_queue_;
    common::Tick update_statistic_tick_;

    DISALLOW_COPY_AND_ASSIGN(DbPoolInfo);
};

}  // namespace block

}  // namespace tenon
