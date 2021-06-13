#include "stdafx.h"
#include "block/db_pool_info.h"

#include "common/encode.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "db/db_utils.h"
#include "block/block_manager.h"

namespace tenon {

namespace block {

static const std::string kPoolHeight = "pool_height";
static const std::string kPoolHash = "pool_hash";
static const std::string kPoolLastBlockStr = "pool_last_block_str";
static const std::string kPoolTimeBlockHeight = "pool_tm_block_height";

DbPoolInfo::DbPoolInfo(uint32_t pool_index) {
    dict_key_ = db::kGlobalDickKeyPoolInfo + "_" + std::to_string(pool_index);
    pool_index_ = pool_index;
}

DbPoolInfo::~DbPoolInfo() {}

int DbPoolInfo::InitWithGenesisBlock() {
    {
        std::lock_guard<std::mutex> guard(base_addr_mutex_);
        if (!base_addr_.empty()) {
            return kBlockSuccess;
        }
    }

    bft::protobuf::Block genesis_block;
    if (BlockManager::Instance()->GetBlockWithHeight(
            common::GlobalInfo::Instance()->network_id(),
            pool_index_,
            0,
            genesis_block) != kBlockSuccess) {
        return kBlockError;
    }

    for (int32_t i = 0; i < genesis_block.tx_list_size(); ++i) {
        if (genesis_block.tx_list(i).from().substr(4, 32) ==
                common::kStatisticFromAddressMidllefix) {
            std::lock_guard<std::mutex> guard(base_addr_mutex_);
            base_addr_ = genesis_block.tx_list(i).from();
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

int DbPoolInfo::SetLastBlock(
        const bft::protobuf::Block& block_item,
        db::DbWriteBach& db_batch) {
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

    *height = common::StringUtil::ToUint64(str_height);
    height_ = *height;
    return kBlockSuccess;
}

int DbPoolInfo::SetTimeBlockHeight(uint64_t height, db::DbWriteBach& db_batch) {
    if (height <= prev_tmblock_with_height_) {
        return kBlockSuccess;
    }

    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kPoolTimeBlockHeight,
            std::to_string(height),
            db_batch)) {
        return kBlockError;
    }

    prev_tmblock_with_height_ = height;
    return kBlockSuccess;
}

int DbPoolInfo::GetTimeBlockHeight(uint64_t* height) {
    if (prev_tmblock_with_height_ != common::kInvalidUint64) {
        *height = prev_tmblock_with_height_;
        return kBlockSuccess;
    }

    std::string str_height;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kPoolTimeBlockHeight,
            &str_height)) {
        BLOCK_ERROR("get height from db failed[%s][%s]",
            dict_key_.c_str(), kPoolTimeBlockHeight.c_str());
        return kBlockError;
    }

    *height = common::StringUtil::ToUint64(str_height);
    prev_tmblock_with_height_ = *height;
    return kBlockSuccess;
}

}  // namespace block

}  // namespace tenon
