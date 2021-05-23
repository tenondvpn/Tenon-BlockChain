#pragma once

#include "common/utils.h"
#include "common/string_utils.h"
#include "db/dict.h"
#include "db/db.h"
#include "block/block_utils.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace block {

class DbPoolInfo {
public:
    DbPoolInfo(uint32_t pool_index);
    ~DbPoolInfo();
    int SetHash(const std::string& hash, db::DbWriteBach& db_batch);
    int GetHash(std::string* hash);
    int SetHeight(uint64_t height, db::DbWriteBach& db_batch);
    int GetHeight(uint64_t* height);
    int SetLastBlock(const bft::protobuf::Block& block_item, db::DbWriteBach& db_batch);
    int GetLastBlockInfo(uint64_t* block_height, uint64_t* block_tm, uint32_t* pool_index);

private:
    std::string dict_key_;
    std::string hash_;
    std::string last_block_str_;
    std::mutex hash_mutex_;
    std::atomic<uint64_t> height_{ common::kInvalidUint64 };
    std::atomic<uint32_t> pool_index_{ common::kInvalidUint32 };
    bft::protobuf::Block last_block_;

    DISALLOW_COPY_AND_ASSIGN(DbPoolInfo);
};

}  // namespace block

}  // namespace tenon
