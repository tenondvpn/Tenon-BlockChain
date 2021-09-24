#include "stdafx.h"
#include "block/db_pool_info.h"

#include "common/encode.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "common/bitmap.h"
#include "db/db_utils.h"
#include "block/block_manager.h"
#include "election/elect_manager.h"

namespace tenon {

namespace block {

static const std::string kPoolHeight = "pool_height";
static const std::string kPoolHash = "pool_hash";
static const std::string kPoolLastBlockStr = "pool_last_block_str";
static const std::string kPoolTimeBlockHeight = "pool_tm_block_height";
static const std::string kPoolTimeBlockWithChainHeight = "pool_tm_with_block_height";

DbPoolInfo::DbPoolInfo(uint32_t pool_index) {
    dict_key_ = db::kGlobalDickKeyPoolInfo + "_" + std::to_string(pool_index);
    pool_index_ = pool_index;
    std::string block_latest_hash;
    GetHash(&block_latest_hash);
}

DbPoolInfo::~DbPoolInfo() {}

int DbPoolInfo::InitWithGenesisBlock() {
    uint32_t id_idx = 0;
    while (true) {
        std::string addr = common::Encode::HexDecode(common::StringUtil::Format(
            "%04d%s%04d",
            common::GlobalInfo::Instance()->network_id(),
            common::kStatisticFromAddressMidllefix.c_str(),
            id_idx++));
        uint32_t pool_idx = common::GetPoolIndex(addr);
        if (pool_idx == pool_index_) {
            std::lock_guard<std::mutex> guard(base_addr_mutex_);
            base_addr_ = addr;
            return kBlockSuccess;
        }
    }

    return kBlockError;
}

std::string DbPoolInfo::GetBaseAddr() {
    {
        std::lock_guard<std::mutex> guard(base_addr_mutex_);
        if (!base_addr_.empty()) {
            return base_addr_;
        }
    }

    // TODO: add to sync
    InitWithGenesisBlock();
    {
        std::lock_guard<std::mutex> guard(base_addr_mutex_);
        if (!base_addr_.empty()) {
            return base_addr_;
        }
    }

    return "";
}

int DbPoolInfo::SetHash(const std::string& hash, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolHash,
            hash,
            db_batch)) {
        return kBlockError;
    }

    std::lock_guard<std::mutex> guard(hash_mutex_);
    hash_ = hash;
    return kBlockSuccess;
}

int DbPoolInfo::GetHash(std::string* hash) {
    {
        std::lock_guard<std::mutex> guard(hash_mutex_);
        if (!hash_.empty()) {
            *hash = hash_;
            return kBlockSuccess;
        }
    }

    std::string tmp_str;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolHash,
            &tmp_str)) {
        return kBlockError;
    }

    *hash = tmp_str;
    {
        std::lock_guard<std::mutex> guard(hash_mutex_);
        hash_ = tmp_str;
    }

    return kBlockSuccess;
}

int DbPoolInfo::GetLastBlockInfo(
        uint64_t* block_height,
        uint64_t* block_tm,
        uint32_t* pool_index) {
    {
        std::lock_guard<std::mutex> guard(hash_mutex_);
        if (!last_block_str_.empty()) {
            *block_height = last_block_.height();
            *block_tm = last_block_.timestamp();
            *pool_index = last_block_.pool_index();
            return kBlockSuccess;
        }
    }

    std::string tmp_str;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolLastBlockStr,
            &tmp_str)) {
        return kBlockError;
    }

    {
        std::lock_guard<std::mutex> guard(hash_mutex_);
        last_block_str_ = tmp_str;
        bool res = last_block_.ParseFromString(last_block_str_);
        assert(res);
    }

    *block_height = last_block_.height();
    *block_tm = last_block_.timestamp();
    *pool_index = last_block_.pool_index();
    return kBlockSuccess;
}

int DbPoolInfo::SetHeight(uint64_t height, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolHeight,
            std::to_string(height),
            db_batch)) {
        return kBlockError;
    }

    height_ = height;
    return kBlockSuccess;
}

int DbPoolInfo::GetHeight(uint64_t* height) {
    if (height_ != common::kInvalidUint64) {
        *height = height_;
        return kBlockSuccess;
    }

    std::string str_height;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolHeight,
            &str_height)) {
        BLOCK_ERROR("get height from db failed[%s][%s]", dict_key_.c_str(), kPoolHeight.c_str());
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(str_height, height)) {
        return kBlockError;
    }

    height_ = *height;
    return kBlockSuccess;
}

int DbPoolInfo::SetTimeBlockHeight(
        uint64_t tmblock_height,
        uint64_t block_height,
        db::DbWriteBach& db_batch) {
    if (prev_tmblock_height_ != common::kInvalidUint64 &&
            tmblock_height <= prev_tmblock_height_) {
        return kBlockSuccess;
    }

    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolTimeBlockHeight,
            std::to_string(tmblock_height),
            db_batch)) {
        return kBlockError;
    }

    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolTimeBlockWithChainHeight,
            std::to_string(block_height),
            db_batch)) {
        return kBlockError;
    }

    prev_tmblock_with_pool_height_ = block_height;
    prev_tmblock_height_ = tmblock_height;
    return kBlockSuccess;
}

int DbPoolInfo::GetTimeBlockHeight(uint64_t* tmblock_height, uint64_t* block_height) {
    if (prev_tmblock_height_ != common::kInvalidUint64 &&
            prev_tmblock_with_pool_height_ != common::kInvalidUint64) {
        *tmblock_height = prev_tmblock_height_;
        *block_height = prev_tmblock_with_pool_height_;
        return kBlockSuccess;
    }

    std::string str_tm_height;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolTimeBlockHeight,
            &str_tm_height)) {
        BLOCK_ERROR("get height from db failed[%s][%s]",
            dict_key_.c_str(), kPoolTimeBlockHeight.c_str());
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(str_tm_height, tmblock_height)) {
        return kBlockError;
    }

    std::string str_block_height;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolTimeBlockWithChainHeight,
            &str_block_height)) {
        BLOCK_ERROR("get height from db failed[%s][%s]",
            dict_key_.c_str(), kPoolTimeBlockWithChainHeight.c_str());
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(str_block_height, block_height)) {
        return kBlockError;
    }

    prev_tmblock_with_pool_height_ = *tmblock_height;
    prev_tmblock_height_ = *block_height;
    return kBlockSuccess;
}

void DbPoolInfo::SetHeightTree(uint64_t height) {
    std::lock_guard<std::mutex> guard(height_tree_mutex_);
    height_tree_.Set(height);
}

void DbPoolInfo::GetMissingHeights(std::vector<uint64_t>* heights) {
    std::lock_guard<std::mutex> guard(height_tree_mutex_);
    height_tree_.GetMissingHeights(heights, height_);
}

void DbPoolInfo::PrintHeightTree() {
    std::lock_guard<std::mutex> guard(height_tree_mutex_);
    height_tree_.PrintTree();
}

}  // namespace block

}  // namespace tenon
