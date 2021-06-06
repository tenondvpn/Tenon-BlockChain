#include "timeblock/time_block_manager.h"

#include <cstdlib>

#include "common/user_property_key_define.h"
#include "common/string_utils.h"
#include "network/network_utils.h"
#include "root/root_utils.h"
#include "timeblock/time_block_utils.h"
#include "bft/bft_utils.h"
#include "security/schnorr.h"
#include "election/proto/elect_proto.h"
#include "dht/dht_key.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace tmblock {

TimeBlockManager* TimeBlockManager::Instance() {
    static TimeBlockManager ins;
    return &ins;
}

uint64_t TimeBlockManager::LatestTimestamp() {
    return latest_time_block_tm_;
}

int TimeBlockManager::LeaderCreateTimeBlockTx(transport::protobuf::Header* msg) {
    msg->set_src_dht_key("");
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg->set_des_dht_key(dht_key.StrKey());
    msg->set_priority(transport::kTransportPriorityHighest);
    msg->set_id(common::GlobalInfo::Instance()->MessageId());
    msg->set_type(common::kBftMessage);
    msg->set_client(false);
    msg->set_hop_count(0);
    auto broad_param = msg->mutable_broadcast();
    elect::ElectProto::SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
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
    msg->set_data(bft_msg.SerializeAsString());
    return kTimeBlockSuccess;
}

int TimeBlockManager::BackupCheckTimeBlockTx(const bft::protobuf::TxInfo& tx_info) {
    if (tx_info.attr_size() != 1) {
        TMBLOCK_ERROR("tx_info.attr_size() error: %d", tx_info.attr_size());
        return kTimeBlockError;
    }

    if (tx_info.attr(0).key() != kAttrTimerBlock) {
        TMBLOCK_ERROR("tx_info.attr(0).key() error: %s", tx_info.attr(0).key().c_str());
        return kTimeBlockError;
    }

    uint64_t leader_tm = common::StringUtil::ToUint64(tx_info.attr(0).value());
    if (!BackupheckNewTimeBlockValid(leader_tm)) {
        TMBLOCK_ERROR("BackupheckNewTimeBlockValid error: %llu", leader_tm);
        return kTimeBlockError;
    }

    return kTimeBlockSuccess;
}

void TimeBlockManager::UpdateTimeBlock(
        uint64_t latest_time_block_height,
        uint64_t latest_time_block_tm) {
    latest_time_block_height_ = latest_time_block_height;
    latest_time_block_tm_ = latest_time_block_tm;
    std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
    latest_time_blocks_.push_back(latest_time_block_tm_);
    if (latest_time_blocks_.size() >= kTimeBlockAvgCount) {
        latest_time_blocks_.pop_front();
    }
}

bool TimeBlockManager::LeaderNewTimeBlockValid(uint64_t* new_time_block_tm) {
    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (now_tm >= latest_time_block_tm_ + kTimeBlockCreatePeriodSeconds) {
        std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
        *new_time_block_tm = latest_time_block_tm_ + kTimeBlockCreatePeriodSeconds;
        if (!latest_time_blocks_.empty()) {
            // Correction time
            auto offset_tm = (latest_time_block_tm_ - latest_time_blocks_.front()) /
                latest_time_blocks_.size();
            if (kTimeBlockCreatePeriodSeconds > offset_tm) {
                *new_time_block_tm += (kTimeBlockCreatePeriodSeconds - offset_tm) *
                    latest_time_blocks_.size();
            } else {
                *new_time_block_tm -= (offset_tm - kTimeBlockCreatePeriodSeconds) *
                    latest_time_blocks_.size();
            }
        }

        return true;
    }

    return false;
}

bool TimeBlockManager::BackupheckNewTimeBlockValid(uint64_t new_time_block_tm) {
    if (!latest_time_blocks_.empty()) {
        // Correction time
        auto offset_tm = (latest_time_block_tm_ - latest_time_blocks_.front()) /
            latest_time_blocks_.size();
        if (kTimeBlockCreatePeriodSeconds > offset_tm) {
            latest_time_block_tm_ += (kTimeBlockCreatePeriodSeconds - offset_tm) *
                latest_time_blocks_.size();
        } else {
            latest_time_block_tm_ -= (offset_tm - kTimeBlockCreatePeriodSeconds) *
                latest_time_blocks_.size();
        }
    }

    latest_time_block_tm_ += kTimeBlockCreatePeriodSeconds;
    if (new_time_block_tm < (latest_time_block_tm_ + kTimeBlockTolerateSeconds) &&
            new_time_block_tm > (latest_time_block_tm_ - kTimeBlockTolerateSeconds)) {
        return true;
    }

    BFT_ERROR("BackupheckNewTimeBlockValid error[%llu][%llu]",
        new_time_block_tm, (uint64_t)latest_time_block_tm_);
    return false;
}

}  // namespace tmblock

}  // namespace tenon
 