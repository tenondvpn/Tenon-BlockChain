#include "block/shard_statistic.h"

#include "bft/bft_utils.h"
#include "bft/dispatch_pool.h"
#include "block/account_manager.h"
#include "common/global_info.h"
#include "election/elect_manager.h"
#include "timeblock/time_block_manager.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace block {

ShardStatistic* ShardStatistic::Instance() {
    static ShardStatistic ins;
    return &ins;
}

void ShardStatistic::AddShardPoolStatistic(
        const std::shared_ptr<bft::protobuf::Block>& block_item) {
    if (block_item->tx_list_size() != 1) {
        return;
    }

    if (block_item->network_id() != common::GlobalInfo::Instance()->network_id()) {
        return;
    }

    bool dispatch_tx = false;
    {
        std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
        if (block_item->timeblock_height() < latest_tm_height_) {
            return;
        }

        if (block_item->timeblock_height() > latest_tm_height_) {
            pool_statistics_.clear();
            g2_for_random_pool_ = std::make_shared<std::mt19937_64>(
                vss::VssManager::Instance()->EpochRandom());
            // avoid slow response transaction pool
            uint32_t valid_pool_count = common::kImmutablePoolSize * 2 / 3;
            valid_pool_.clear();
            while (valid_pool_.size() < valid_pool_count) {
                valid_pool_.insert((*g2_for_random_pool_)() % common::kImmutablePoolSize);
            }

            latest_tm_height_ = block_item->timeblock_height();
        }

            block_item->timeblock_height(), block_item->electblock_height(), block_item->pool_index());
        if (valid_pool_.empty()) {
            return;
        }

        if (valid_pool_.find(block_item->pool_index()) == valid_pool_.end()) {
            return;
        }

        for (int32_t i = 0; i < block_item->tx_list(0).storages_size(); ++i) {
            if (block_item->tx_list(0).storages(i).key() == bft::kStatisticAttr) {
                block::protobuf::StatisticInfo statistic_info;
                if (statistic_info.ParseFromString(block_item->tx_list(0).storages(i).value())) {
                    if (statistic_info.elect_height() < latest_elect_height_) {
                        return;
                    }

                    if (statistic_info.elect_height() > latest_elect_height_) {
                        latest_elect_height_ = statistic_info.elect_height();
                        pool_statistics_.clear();
                        for (int32_t i = 0; i < statistic_info.succ_tx_count_size(); ++i) {
                            pool_statistics_[i] = statistic_info.succ_tx_count(i);
                        }

                        elect_member_count_ = statistic_info.succ_tx_count_size();
                    } else {
                        if (elect_member_count_ != statistic_info.succ_tx_count_size()) {
                            BLOCK_ERROR("invalid elect member count[%u][%u]",
                                elect_member_count_, statistic_info.succ_tx_count_size());
                            // assert(false); 
                            return;
                        }

                        for (int32_t i = 0; i < statistic_info.succ_tx_count_size(); ++i) {
                            pool_statistics_[i] += statistic_info.succ_tx_count(i);
                        }
                    }

                    all_tx_count_ += statistic_info.all_tx_count();
                }

                break;
            }
        }

        valid_pool_.erase(block_item->pool_index());
        if (valid_pool_.empty()) {
            dispatch_tx = true;
        }

        latest_tm_height_ = block_item->timeblock_height();
    }

    if (dispatch_tx) {
        CreateStatisticTransaction();
    }
}

void ShardStatistic::GetStatisticInfo(block::protobuf::StatisticInfo* statistic_info) {
    std::lock_guard<std::mutex> guard(pool_statistics_mutex_);
    statistic_info->set_all_tx_count(all_tx_count_);
    statistic_info->set_timeblock_height(latest_tm_height_);
    statistic_info->set_elect_height(latest_tm_height_);
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

        tx_info.set_gid(std::string("ft") +
            common::Hash::Hash256(
                std::to_string(tmblock::TimeBlockManager::Instance()->LatestTimestamp())) +
            std::to_string(pool_idx));
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
        auto statistic_attr = tx_info.add_attr();
        statistic_attr->set_key(bft::kStatisticAttr);
        statistic_attr->set_value(statistic_info.SerializeAsString());
        if (bft::DispatchPool::Instance()->Dispatch(tx_info) != bft::kBftSuccess) {
            BFT_ERROR("CreateStatisticTransaction dispatch pool failed!");
        }

        BFT_ERROR("CreateStatisticTransaction dispatch pool success! super leader: %s", common::Encode::HexEncode(*iter).c_str());
    }
}

}  // namespace block

}  // namespace tenon
