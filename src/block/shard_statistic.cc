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

    AddStatistic(block_ptr);
}

void ShardStatistic::AddStatistic(const std::shared_ptr<bft::protobuf::Block>& block_item) {
    if (block_item->network_id() != common::GlobalInfo::Instance()->network_id()) {
        return;
    }

    std::shared_ptr<StatisticItem> min_st_ptr = statistic_items_[0];
    std::shared_ptr<StatisticItem> match_st_ptr = nullptr;
    for (uint32_t i = 0; i < kStatisticMaxCount; ++i) {
        if (min_st_ptr->tmblock_height > statistic_items_[i]->tmblock_height) {
            min_st_ptr = statistic_items_[i];
        }

        if (statistic_items_[i]->tmblock_height == block_item->timeblock_height()) {
            match_st_ptr = statistic_items_[i];
            break;
        }
    }

    if (match_st_ptr == nullptr) {
        match_st_ptr = min_st_ptr;
    }

    StatisticElectItemPtr min_ec_ptr = match_st_ptr->elect_items[0];
    StatisticElectItemPtr match_ec_ptr = nullptr;
    for (uint32_t i = 0; i < kStatisticMaxCount; ++i) {
        if (min_ec_ptr->elect_height < match_st_ptr->elect_items[i]->elect_height) {
            min_ec_ptr = match_st_ptr->elect_items[i];
        }

        if (block_item->electblock_height() == match_st_ptr->elect_items[i]->elect_height) {
            match_ec_ptr = match_st_ptr->elect_items[i];
            break;
        }
    }

    if (match_ec_ptr == nullptr) {
        match_ec_ptr = min_ec_ptr;
    }

    auto ext_iter = match_st_ptr->added_height.find(block_item->height());
    if (ext_iter != match_st_ptr->added_height.end()) {
        return;
    }

    match_st_ptr->added_height.insert(block_item->height());
    match_st_ptr->tmblock_height = block_item->timeblock_height();
    match_st_ptr->all_tx_count += block_item->tx_list_size();
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

        ++match_ec_ptr->succ_tx_count[i];
    }
}

int ShardStatistic::GetStatisticInfo(
        uint64_t timeblock_height,
        block::protobuf::StatisticInfo* statistic_info) {
    for (uint32_t i = 0; i < kStatisticMaxCount; ++i) {
        if (statistic_items_[i]->tmblock_height != timeblock_height) {
            continue;
        }

        statistic_info->set_timeblock_height(statistic_items_[i]->tmblock_height);
        statistic_info->set_all_tx_count(statistic_items_[i]->all_tx_count);
        for (uint32_t elect_idx = 0; elect_idx < kStatisticMaxCount; ++elect_idx) {
            if (statistic_items_[i]->elect_items[elect_idx]->elect_height == 0) {
                continue;
            }

            auto elect_st = statistic_info->add_elect_statistic();
            elect_st->set_elect_height(
                statistic_items_[i]->elect_items[elect_idx]->elect_height);
            auto member_count = elect::ElectManager::Instance()->GetMemberCountWithHeight(
                elect_st->elect_height(),
                common::GlobalInfo::Instance()->network_id());
            for (uint32_t i = 0; i < member_count; ++i) {
                elect_st->add_succ_tx_count(
                    statistic_items_[i]->elect_items[elect_idx]->succ_tx_count[i]);
            }
        }
    }
}

}  // namespace block

}  // namespace tenon
