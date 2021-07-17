#include "block/shard_statistic.h"

#include "common/global_info.h"
#include "common/encode.h"
#include "bft/bft_utils.h"
#include "bft/dispatch_pool.h"
#include "block/account_manager.h"
#include "election/elect_manager.h"
#include "timeblock/time_block_manager.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace block {

static const std::string kShardFinalStaticPrefix = common::Encode::HexDecode("027a252b30589b8ed984cf437c475b069d0597fc6d51ec6570e95a681ffa9fe7");

ShardStatistic* ShardStatistic::Instance() {
    static ShardStatistic ins;
    return &ins;
}

void ShardStatistic::AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_ptr) {
    if (block_ptr->bitmap_size() == 0) {
        BLOCK_ERROR("block bitmap size empty: height: %lu, hash: %s",
            block_ptr->height(), common::Encode::HexEncode(block_ptr->hash()).c_str());
        return;
    }

    std::lock_guard<std::mutex> guard(block_statistic_queue_mutex_);
    block_statistic_queue_.push(block_ptr);
}

void ShardStatistic::SatisticBlock() {
    while (block_statistic_queue_.size() > 0) {
        std::shared_ptr<bft::protobuf::Block> block_ptr = nullptr;
        if (!block_statistic_queue_.pop(&block_ptr)) {
            break;
        }

        if (block_ptr != nullptr) {
            AddStatistic(block_ptr);
        }
    }
}

int ShardStatistic::AddStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item) {
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
        }
        else {
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

    uint32_t member_count = elect::ElectManager::Instance()->GetMemberCount(
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

int ShardStatistic::GetSinglePoolStatisticInfo(block::protobuf::StatisticInfo* statistic_info) {
    SatisticBlock();
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
    uint32_t member_count = elect::ElectManager::Instance()->GetMemberCount(
        st_item_ptr->elect_height,
        common::GlobalInfo::Instance()->network_id());
    for (uint32_t i = 0; i < member_count; ++i) {
        statistic_info->add_succ_tx_count(st_item_ptr->succ_tx_count[i]);
    }

    return kBlockSuccess;
}

void ShardStatistic::TickSatisticBlock() {
    if (common::GlobalInfo::Instance()->network_id() >= network::kRootCongressNetworkId &&
        common::GlobalInfo::Instance()->network_id() < network::kConsensusShardEndNetworkId) {
        update_statistic_tick_.Destroy();
        return;
    }

    SatisticBlock();
    update_statistic_tick_.CutOff(
        kUpdateStatisticPeriod,
        std::bind(&ShardStatistic::TickSatisticBlock, this));
}

void ShardStatistic::AddShardPoolStatistic(
        const std::shared_ptr<bft::protobuf::Block>& block_item) {
    if (block_item->pool_index() >= common::kImmutablePoolSize) {
        return;
    }

    if (block_item->tx_list_size() != 1) {
        BLOCK_ERROR("block_item->tx_list_size() != 1: %d", block_item->tx_list_size());
        return;
    }

    if (!network::IsSameShardOrSameWaitingPool(
            common::GlobalInfo::Instance()->network_id(),
            block_item->network_id())) {
        BLOCK_ERROR("network invalid local: %d, block: %d",
            common::GlobalInfo::Instance()->network_id(),
            block_item->network_id());
        return;
    }

    if (block_item->timeblock_height() < latest_tm_height_) {
        BLOCK_ERROR("block_item->timeblock_height() < latest_tm_height_[%lu][%lu]",
            block_item->timeblock_height(),
            (uint64_t)latest_tm_height_);
        return;
    }

    {
        if (block_item->timeblock_height() > latest_tm_height_) {
            std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
            if (block_item->timeblock_height() > latest_tm_height_) {
                memset(pool_statistics_, 0, sizeof(pool_statistics_));
                valid_pool_.clear();
                latest_tm_height_ = block_item->timeblock_height();
                all_tx_count_ = 0;
            }
        }

        {
            std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
            if (valid_pool_.Valid(block_item->pool_index())) {
                return;
            }

            valid_pool_.Set(block_item->pool_index());
        }

        for (int32_t i = 0; i < block_item->tx_list(0).storages_size(); ++i) {
            if (block_item->tx_list(0).storages(i).key() == bft::kStatisticAttr) {
                block::protobuf::StatisticInfo statistic_info;
                if (statistic_info.ParseFromString(block_item->tx_list(0).storages(i).value())) {
                    if (statistic_info.elect_height() > latest_elect_height_) {
//                         std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
//                         if (statistic_info.elect_height() > latest_elect_height_) {
//                             memset(pool_statistics_, 0, sizeof(pool_statistics_));
                            latest_elect_height_ = statistic_info.elect_height();
//                         }
                    }

                    for (int32_t i = 0; i < statistic_info.succ_tx_count_size(); ++i) {
                        pool_statistics_[i] += statistic_info.succ_tx_count(i);
                    }

                    all_tx_count_ += statistic_info.all_tx_count();
                }

                break;
            }
        }
    }

    bool create_tx = false;
    {
        std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
        if (valid_pool_.valid_count() >= common::kImmutablePoolSize) {
            create_tx = true;
        }
    }

    std::string invalid_pools;
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        if (!valid_pool_.Valid(i)) {
            invalid_pools += std::to_string(i) + " ";
        }
    }

//     BLOCK_DEBUG("valid_pool_.valid_count(): %d, need: %d, invalid_pools: %s", valid_pool_.valid_count(), common::kImmutablePoolSize, invalid_pools.c_str());
    if (create_tx) {
        CreateStatisticTransaction();
    }
}

void ShardStatistic::GetStatisticInfo(block::protobuf::StatisticInfo* statistic_info) {
    statistic_info->set_all_tx_count(all_tx_count_);
    statistic_info->set_timeblock_height(latest_tm_height_);
    statistic_info->set_elect_height(latest_elect_height_);
    for (int32_t i = 0; i < elect_member_count_; ++i) {
        statistic_info->add_succ_tx_count(pool_statistics_[i]);
    }
}

void ShardStatistic::CreateStatisticTransaction() {
    auto super_leader_ids = elect::ElectManager::Instance()->leaders(
        common::GlobalInfo::Instance()->network_id());
    if (super_leader_ids.empty()) {
        return;
    }

    auto leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        common::GlobalInfo::Instance()->network_id());
    // avoid the unreliability of a single leader
    for (auto iter = super_leader_ids.begin(); iter != super_leader_ids.end(); ++iter) {
        int32_t pool_idx = 0;
        auto mem_ptr = elect::ElectManager::Instance()->GetMember(
            common::GlobalInfo::Instance()->network_id(),
            *iter);
        for (pool_idx = 0; pool_idx < (int32_t)common::kImmutablePoolSize; ++pool_idx) {
            if (pool_idx % leader_count == mem_ptr->pool_index_mod_num) {
                break;
            }
        }

        bft::protobuf::TxInfo tx_info;
        tx_info.set_type(common::kConsensusFinalStatistic);
        tx_info.set_from(block::AccountManager::Instance()->GetPoolBaseAddr(pool_idx));
        if (tx_info.from().empty()) {
            return;
        }

        tx_info.set_gid(common::Hash::Hash256(
            kShardFinalStaticPrefix +
            std::to_string(elect::ElectManager::Instance()->latest_height(common::GlobalInfo::Instance()->network_id())) +
            std::to_string(tmblock::TimeBlockManager::Instance()->LatestTimestamp())) +
            "_" +
            std::to_string(pool_idx));
//         BLOCK_DEBUG("create new final statistic time stamp: %lu",
//             tmblock::TimeBlockManager::Instance()->LatestTimestamp());
        tx_info.set_gas_limit(0llu);
        tx_info.set_amount(0);
        tx_info.set_network_id(common::GlobalInfo::Instance()->network_id());
        auto height_attr = tx_info.add_attr();
        height_attr->set_key(tmblock::kAttrTimerBlockHeight);
        height_attr->set_value(std::to_string(
            tmblock::TimeBlockManager::Instance()->LatestTimestampHeight()));
        auto tm_attr = tx_info.add_attr();
        tm_attr->set_key(tmblock::kAttrTimerBlockTm);
        tm_attr->set_value(std::to_string(
            tmblock::TimeBlockManager::Instance()->LatestTimestamp()));
        block::protobuf::StatisticInfo statistic_info;
        GetStatisticInfo(&statistic_info);
        auto statistic_attr = tx_info.add_storages();
        statistic_attr->set_key(bft::kStatisticAttr);
        statistic_attr->set_value(statistic_info.SerializeAsString());
        if (bft::DispatchPool::Instance()->Dispatch(tx_info) != bft::kBftSuccess) {
            BFT_ERROR("CreateStatisticTransaction dispatch pool failed!");
        }

        break;
    }
}

}  // namespace block

}  // namespace tenon
