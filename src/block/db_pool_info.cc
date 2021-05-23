#include "stdafx.h"
#include "block/db_pool_info.h"

#include "common/encode.h"
#include "db/db_utils.h"

namespace tenon {

namespace block {

static const std::string kPoolHeight = "pool_height";
static const std::string kPoolHash = "pool_hash";
static const std::string kPoolLastBlockStr = "pool_last_block_str";

DbPoolInfo::DbPoolInfo(uint32_t pool_index) {
    dict_key_ = db::kGlobalDickKeyPoolInfo + "_" + std::to_string(pool_index);
    pool_index_ = pool_index;
}

DbPoolInfo::~DbPoolInfo() {}

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

int DbPoolInfo::SetLastBlock(const bft::protobuf::Block& block_item, db::DbWriteBach& db_batch) {
    std::string block_str = block_item.SerializeAsString();
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolLastBlockStr,
            block_str,
            db_batch)) {
        return kBlockError;
    }

    std::lock_guard<std::mutex> guard(hash_mutex_);
    last_block_str_ = block_str;
    last_block_ = block_item;
    return kBlockSuccess;
}

int DbPoolInfo::GetLastBlockInfo(uint64_t* block_height, uint64_t* block_tm, uint32_t* pool_index) {
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

    *height = common::StringUtil::ToUint64(str_height);
    height_ = *height;
    return kBlockSuccess;
}

}  // namespace block

}  // namespace tenon
