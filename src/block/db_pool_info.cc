#include "stdafx.h"
#include "block/db_pool_info.h"

#include "common/encode.h"
#include "db/db_utils.h"

namespace tenon {

namespace block {

static const std::string kPoolHeight = "pool_height";
static const std::string kPoolHash = "pool_hash";

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
