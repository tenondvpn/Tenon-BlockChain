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

    BLOCK_DEBUG("valid_pool_.valid_count(): %d, need: %d", valid_pool_.valid_count(), common::kImmutablePoolSize);
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
        BLOCK_DEBUG("create new final statistic time stamp: %lu",
            tmblock::TimeBlockManager::Instance()->LatestTimestamp());
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
