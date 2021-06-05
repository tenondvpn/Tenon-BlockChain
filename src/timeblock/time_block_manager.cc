#include "timeblock/time_block_manager.h"

#include <cstdlib>

#include "common/user_property_key_define.h"
#include "common/string_utils.h"
#include "network/network_utils.h"
#include "root/root_utils.h"
#include "timeblock/time_block_utils.h"
#include "bft/bft_utils.h"
#include "security/schnorr.h"

namespace tenon {

namespace tmblock {

TimeBlockManager* TimeBlockManager::Instance() {
    static TimeBlockManager ins;
    return &ins;
}

uint64_t TimeBlockManager::LatestTimestamp() {
    return latest_time_block_tm_;
}

int TimeBlockManager::LeaderCreateTimeBlockTx(bft::protobuf::BftMessage& bft_msg) {
    uint64_t new_time_block_tm = 0;
    if (!LeaderNewTimeBlockValid(&new_time_block_tm)) {
        return kTimeBlockError;
    }

    bft::protobuf::TxBft tx_bft;
    auto tx_info = tx_bft.mutable_new_tx();
    tx_info->set_type(common::kConsensusRootTimeBlock);
    tx_info->set_from(root::kRootChainSingleBlockTxAddress);
    tx_info->set_gas_limit(0llu);
    tx_info->set_amount(0);
    tx_info->set_network_id(network::kRootCongressNetworkId);
    auto all_exits_attr = tx_info->add_attr();
    all_exits_attr->set_key(kAttrTimerBlock);
    all_exits_attr->set_value(std::to_string(new_time_block_tm));

    bft_msg.set_net_id(network::kRootCongressNetworkId);
    bft_msg.set_data(tx_bft.SerializeAsString());
    bft_msg.set_gid(common::CreateGID(""));
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_node_id(common::GlobalInfo::Instance()->id());
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto hash128 = bft::GetTxMessageHash(*tx_info);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign)) {
        return kTimeBlockError;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    return kTimeBlockSuccess;
}

int TimeBlockManager::BackupCheckTimeBlockTx(const bft::protobuf::TxInfo& tx_info) {
    if (tx_info.attr_size() != 1) {
        return kTimeBlockError;
    }

    if (tx_info.attr(0).key() != kAttrTimerBlock) {
        return kTimeBlockError;
    }

    uint64_t leader_tm = common::StringUtil::ToUint64(tx_info.attr(0).value());
    if (!BackupheckNewTimeBlockValid(leader_tm)) {
        return kTimeBlockError;
    }

    return kTimeBlockSuccess;
}

void TimeBlockManager::UpdateTimeBlock(
        uint64_t latest_time_block_height,
        uint64_t latest_time_block_tm) {
    latest_time_block_height_ = latest_time_block_height;
    latest_time_block_tm_ = latest_time_block_tm;
    latest_time_block_local_tm_ = common::TimeUtils::TimestampSeconds();
    std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
    latest_time_blocks_.push_back(latest_time_block_tm_);
    if (latest_time_blocks_.size() >= kTimeBlockAvgCount) {
        latest_time_blocks_.pop_front();
    }
}

bool TimeBlockManager::LeaderNewTimeBlockValid(uint64_t* new_time_block_tm) {
    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (now_tm - latest_time_block_local_tm_ >= kTimeBlockCreatePeriodSeconds) {
        std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
        // Correction time
        *new_time_block_tm = latest_time_block_tm_ +
            (now_tm - latest_time_block_local_tm_) +
            (latest_time_block_tm_ - latest_time_blocks_.front()) /
            (kTimeBlockCreatePeriodSeconds * kTimeBlockAvgCount);
        return true;
    }

    return false;
}

bool TimeBlockManager::BackupheckNewTimeBlockValid(uint64_t new_time_block_tm) {
    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (abs((int64_t)new_time_block_tm - (int64_t)latest_time_block_tm_) <
            (int64_t)kTimeBlockTolerateSeconds) {
        return true;
    }

    return false;
}

}  // namespace tmblock

}  // namespace tenon