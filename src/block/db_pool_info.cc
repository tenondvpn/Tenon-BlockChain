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
    //assert(!hash_.empty());
    LoadBlocksUtilLatestStatisticBlock();
//     TickSatisticBlock();
//     update_statistic_tick_.CutOff(
//         kUpdateStatisticPeriod,
//         std::bind(&DbPoolInfo::TickSatisticBlock, this));
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

int DbPoolInfo::LoadBlocksUtilLatestStatisticBlock() {
    std::string prev_hash;
    {
        std::lock_guard<std::mutex> guard(hash_mutex_);
        prev_hash = hash_;
    }

    while (true) {
        std::string block_str;
        auto st = db::Db::Instance()->Get(prev_hash, &block_str);
        if (!st.ok()) {
            // TODO: add to sync
            return kBlockError;
        }

        auto block_item = std::make_shared<bft::protobuf::Block>();
        if (!block_item->ParseFromString(block_str)) {
            return kBlockError;
        }

        AddStatistic(block_item);
        if (block_item->tx_list_size() == 1 &&
                block_item->tx_list(0).type() == common::kConsensusStatistic) {
            break;
        }

        prev_hash = block_item->prehash();
        if (prev_hash.empty()) {
            break;
        }
    }

    return kBlockSuccess;
}

void DbPoolInfo::AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_ptr) {
    if (block_ptr->bitmap_size() == 0) {
        BLOCK_ERROR("block bitmap size empty: height: %lu, hash: %s",
            block_ptr->height(), common::Encode::HexEncode(block_ptr->hash()).c_str());
        return;
    }

//     AddStatistic(block_ptr);
}

void DbPoolInfo::SatisticBlock() {
    while (block_statistic_queue_.size() > 0) {
        std::shared_ptr<bft::protobuf::Block> block_ptr = nullptr;
        {
            std::lock_guard<std::mutex> guard(block_statistic_queue_mutex_);
            block_ptr = block_statistic_queue_.front();
            block_statistic_queue_.pop();
        }

        if (block_ptr != nullptr) {
            AddStatistic(block_ptr);
        }
    }
}

int DbPoolInfo::AddStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item) {
    // TODO: sync thread to load block
    std::shared_ptr<StatisticItem> st_item_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(statistic_for_tmblock_mutex_);
        if (block_item->timeblock_height() > max_time_block_height_) {
            max_time_block_height_ = block_item->timeblock_height();
        }

        auto iter = statistic_for_tmblock_.find(block_item->timeblock_height());
        // use max elect height
        if (iter == statistic_for_tmblock_.end() ||
            block_item->electblock_height() > iter->second->elect_height) {
            st_item_ptr = std::make_shared<StatisticItem>();
            statistic_for_tmblock_[block_item->timeblock_height()] = st_item_ptr;
        } else {
            st_item_ptr = iter->second;
        }
    }
    
    {
        std::lock_guard<std::mutex> guard(st_item_ptr->added_height_mutex);
        auto ext_iter = st_item_ptr->added_height.find(block_item->height());
        if (ext_iter != st_item_ptr->added_height.end()) {
            return kBlockSuccess;
        }

        st_item_ptr->added_height.insert(block_item->height());
    }

    st_item_ptr->tmblock_height = block_item->timeblock_height();
    st_item_ptr->elect_height = block_item->electblock_height();
    st_item_ptr->all_tx_count += block_item->tx_list_size();
    std::vector<uint64_t> bitmap_data;
    for (int32_t i = 0; i < block_item->bitmap_size(); ++i) {
        bitmap_data.push_back(block_item->bitmap(i));
    }

    uint32_t member_count = elect::ElectManager::Instance()->GetMemberCountWithHeight(
        block_item->electblock_height(),
        block_item->network_id());
    common::Bitmap final_bitmap(bitmap_data);
    uint32_t bit_size = final_bitmap.data().size() * 64;
    assert(member_count <= bit_size);
    assert(member_count <= common::kEachShardMaxNodeCount);
    for (uint32_t i = 0; i < member_count; ++i) {
        if (!final_bitmap.Valid(i)) {
            continue;
        }

        ++st_item_ptr->succ_tx_count[i];
    }

    if (max_time_block_height_ > 2) {
        if (statistic_for_tmblock_.size() > 2) {
            for (int64_t i = (int64_t)max_time_block_height_ - 2; i > 0; --i) {
                std::lock_guard<std::mutex> guard(statistic_for_tmblock_mutex_);
                auto iter = statistic_for_tmblock_.find(i);
                if (iter == statistic_for_tmblock_.end()) {
                    break;
                }

                statistic_for_tmblock_.erase(iter);
            }
        }
    }

    return kBlockSuccess;
}

int DbPoolInfo::GetSinglePoolStatisticInfo(block::protobuf::StatisticInfo* statistic_info) {
//     SatisticBlock();
    std::shared_ptr<StatisticItem> st_item_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(statistic_for_tmblock_mutex_);
        auto iter = statistic_for_tmblock_.find(max_time_block_height_);
        if (iter == statistic_for_tmblock_.end()) {
            return kBlockError;
        }

        st_item_ptr = iter->second;
    }
    
    statistic_info->set_timeblock_height(st_item_ptr->tmblock_height);
    statistic_info->set_elect_height(st_item_ptr->elect_height);
    statistic_info->set_all_tx_count(st_item_ptr->all_tx_count);
    uint32_t member_count = elect::ElectManager::Instance()->GetMemberCountWithHeight(
        st_item_ptr->elect_height,
        common::GlobalInfo::Instance()->network_id());
    for (uint32_t i = 0; i < member_count; ++i) {
        statistic_info->add_succ_tx_count(st_item_ptr->succ_tx_count[i]);
    }

    return kBlockSuccess;
}

void DbPoolInfo::TickSatisticBlock() {
    if (common::GlobalInfo::Instance()->network_id() >= network::kRootCongressNetworkId &&
            common::GlobalInfo::Instance()->network_id() < network::kConsensusShardEndNetworkId) {
        update_statistic_tick_.Destroy();
        return;
    }

    SatisticBlock();
    update_statistic_tick_.CutOff(
        kUpdateStatisticPeriod,
        std::bind(&DbPoolInfo::TickSatisticBlock, this));
}

}  // namespace block

}  // namespace tenon
